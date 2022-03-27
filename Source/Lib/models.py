"""
Shared models for logger and API
"""

import sys
import requests
import jsonpickle
import logging
import json
import cysimdjson
from requests.models import HTTPError

logger = logging.getLogger(__name__)


class DictObj():
    """
    Dict object currently used to wrap config dicts to a objects for easier
    manipulation. Taken from
    https://stackoverflow.com/questions/1305532/convert-nested-python-dict-to-object
    """

    def __init__(self, in_dict: dict):
        assert isinstance(in_dict, dict)
        for key, val in in_dict.items():
            if isinstance(val, (list, tuple)):
                setattr(self, key, [DictObj(x) if isinstance(
                    x, dict) else x for x in val])
            else:
                setattr(self, key, DictObj(val)
                        if isinstance(val, dict) else val)


class LogSource():
    """
    Object used to wrap each log source as defined in the config file
    """

    def __init__(self, name, path, max_alerts, fields, reliability):
        self.ids_name = name
        self.log_path = path
        """
        is_valid will become false if the target log file is missing or broken.
        Used to prevent the logger from constantly polling invalid log sources.
        """
        self.is_valid = True
        # should be a list of ids alert objects
        self.alerts = []
        if hasattr(fields, "severity"):
            self.alert_fields = AlertFields(dest_ip=fields.dest_ip,
                                            message=fields.message,
                                            src_ip=fields.src_ip,
                                            timestamp=fields.timestamp,
                                            severity=fields.severity,
                                            category=fields.category)
        else:
            self.alert_fields = AlertFields(dest_ip=fields.dest_ip,
                                            message=fields.message,
                                            src_ip=fields.src_ip,
                                            timestamp=fields.timestamp,
                                            category=fields.category)
        """
        Set the maximum number of alerts to read every time the source is
        parsed. Note, that invalid alerts do not increase this count so this is
        ultimately a messure of the amount of maximum number of alerts that are
        forwarded to the API everytime the parser gets called.
        20 alerts seem to be a good default, at least for Suricata
        """
        self.max_alerts = max_alerts
        self.last_alert_index = 0
        self.alerts_read = 0
        """
        The reliability rating is used to weigh alerts form certain IDS 
        in the scoring algorithm 
        """
        self.reliability = reliability
        self.last_alert_timestamp = ""
        self.last_alert_message = ""

    def __repr__(self):
        return "{},{}".format(self.ids_name, self.log_path)


class AlertFields():
    """
    Wrapper class to set the names for each alert field in the JSON
    """

    def __init__(self, dest_ip, src_ip, message, timestamp, category,
                 **severity):
        self.dest_ip = dest_ip
        self.src_ip = src_ip
        self.message = message
        self.timestamp = timestamp
        self.category = category
        """
        not all IDS give a severity to alerts so, this is need to account for
        that.
        """
        if severity:
            self.severity = severity["severity"]

    def __repr__(self):
        if hasattr(self, "severity"):
            if self.severity:
                return "{},{},{},{},{},{},{}".format(
                    self.dest_ip, self.src_ip, self.message, self.category,
                    self.timestamp, self.severity
                )
        return "{},{},{},{},{}".format(
            self.dest_ip, self.src_ip, self.message, self.category,
            self.timestamp
        )


class IDSAlert():
    """
    Wrapper for IDS alerts primarily, used by the logger as a way to construct
    valid JSON before, forwarding each alert to the API.
    """

    def __init__(
        self, dest_ip, src_ip, message, timestamp, log_source, category,
        **severity
    ):
        self.dest_ip = dest_ip
        self.src_ip = src_ip
        self.message = message
        self.timestamp = timestamp
        self.log_source = log_source
        self.category = category
        if severity:
            self.severity = severity["severity"]

    def __repr__(self):
        return "{},{},{},{},{},{}".format(
            self.timestamp, self.src_ip, self.dest_ip, self.message,
            self.category, self.log_source.ids_name)


class APIConnection():
    """
    Used to represent the status of and connection settings used by the API.
    Also used to handle every client to server interaction with the API
    """

    def __init__(self, target_url, polling_rate, api_id_file, api_key_file,
                 status_endpoint, events_endpoint, max_retries, is_enabled):
        self.url = target_url
        self.polling_rate = polling_rate

        # Don't catch this
        self.id, self.key = self.load_api_creds(
            api_id_file, api_key_file)

        self.status_endpoint = status_endpoint
        self.forward_endpoint = events_endpoint
        self.max_retries = max_retries
        self.current_retries = 0
        self.is_enabled = is_enabled

    def get_api_status(self):
        """
        Sends a request the status endpoint as defined in the config file
        """
        headers = {"user-agent": "ctfscore-log/0.1"}
        target_url = self.url + self.status_endpoint
        try:
            status_request = requests.get(url=target_url, headers=headers, verify=False)
            if status_request.status_code == 200:
                return True
            return False
        except HTTPError as http_error:
            logger.error((
                "The following http error has occurred: %s", http_error.args))
            return False
        except (requests.ConnectionError, requests.ConnectTimeout,
                requests.RequestException) as connect_error:
            logger.error((
                "The following connection error has occurred: %s",
                connect_error.args
            ))
            return False

    def load_api_creds(self, api_id_file, api_key_file):
        """
        Reads from the credential files specified in the config file and loads
        the value of the key and id. Only, if they pass basic validation
        """
        with open(api_id_file, "r", encoding="utf-8") as id_file:
            api_id = id_file.readline()
        with open(api_key_file, "r", encoding="utf-8") as api_key_file:
            api_key = api_key_file.readline()

        if len(api_id) == 0 or len(api_id) > 128 or len(api_key) == 0 or len(api_key) > 256:
            raise ValueError('The api connection files are invalid')

        return api_id, api_key

    def forward_IDS_alerts(self, alerts, **is_verbose):
        """
        Forwards the specified IDS alerts to the api via the forwarding
        endpoint as specified by the config.
        """

        """
        Concatianate the alert sources together to reduce faffage on the 
        server side
        """
        target_url = self.url + self.forward_endpoint
        merged_alerts = []
        for source in alerts:
            merged_alerts.append(source)
        headers = {"user-agent": "ctfscore-log/1.0b"}
        if self.max_retries > 0 and self.current_retries == self.max_retries:
            """
            Stop execution if x number of requests have occurred since last
            successfull request. Usefull for killing containerised deployments
            of the log aggergator
            """
            logger.error(
                "The max number of HTTP retries ({}) has been exceeded".format(
                    self.max_retries)
            )
            sys.exit("Max number of http retries exceeded")
        try:
            if len(merged_alerts) > 0:
                logger.info((
                    "Forwarding the following to the API: %s", merged_alerts))
                request_json = jsonpickle.encode(merged_alerts, make_refs=False)
                final_json = APIRequest(request_json, self.key, self.id)
                if is_verbose:
                    print(jsonpickle.encode(final_json, indent=1))
                api_request = requests.post(
                    url=target_url,
                    json=jsonpickle.encode(final_json), headers=headers, verify=False)
                if is_verbose:
                    print(api_request.status_code)
                if not api_request.status_code == 200:
                    self.current_retries += 1
                    return False
                self.current_retries = 0
                return True
        except HTTPError as http_error:
            self.current_retries += 1
            logger.error((
                "The following http error has occurred: %s", http_error.args))
            return False
        except (requests.ConnectionError, requests.ConnectTimeout,
                requests.RequestException) as connect_error:
            self.current_retries += 1
            logger.error((
                "The following connection error has occurred: %s",
                connect_error.args
            ))
            return False
        except OSError as os_error:
            self.current_retries += 1
            logger.error((
                "The following os_error has occurred: %s", os_error.args)
            )
            return False


class APIRequest():
    """
    Wrapper for API requests contains, both creds and the request content. 
    Needed to make serialising JSON a lot more straightforward
    """

    def __init__(self, json, key, id):
        self.request_content = json
        self.key = key
        self.id = id
