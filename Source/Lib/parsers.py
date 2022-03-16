"""
Parsers for each log file format
Reading JSON takes ages with the default module and even with some of the
'fast' third party modules. So we need to use cysimdjson
"""
from doctest import Example
import logging
import cysimdjson
import json

import random
import jsonpickle

import orjson
import ujson

from Lib.models import IDSAlert


logger = logging.getLogger(__name__)


"""SUPPORTED_JSON_PARSERS = ["json", "orjson",
                          "ujson", "cysimdjson", "jsonpickle"]"""

SUPPORTED_JSON_PARSERS = ["json","cysimdjson", "orjson","ujson", "jsonpickle"]


def parse_single_line_json(source, **kwargs):
    """
    This func handles log files that store individual alerts as valid JSON but,
    do not store alerts in a valid list and instead dump each alert
    sequentially.
    The IDS that are currently known to follow this format are:
    1. Suricata
    2. teler
    3. wazuh
    """

    alerts = []
    lower_name = source.ids_name.lower()
    if kwargs.get("is_rand_json", None):
        targeted_parser = random.choice(SUPPORTED_JSON_PARSERS)
        if targeted_parser in ["json","orjson","ujson", "jsonpickle"]:
            with open(source.log_path, "rb") as log_file:
                log_file.seek(source.last_alert_index, 0)
                for line in log_file:
                    try:
                        if targeted_parser == "json":
                            alert = json.loads(line)
                        elif targeted_parser == "orjson":
                            alert = orjson.loads(line)
                        elif targeted_parser == "ujson":
                            alert = ujson.loads(line)
                        elif targeted_parser == "jsonpickle":
                            alert = jsonpickle.loads(line)
                    except Exception as e:
                        source.last_alert_index += len(line)
                        break
                    if lower_name == "suricata"\
                            and alert["event_type"] == "alert"\
                            or lower_name == "teler":
                        if alert['alert']['severity']:
                            alerts.append(IDSAlert(
                                dest_ip=alert["dest_ip"],
                                src_ip=alert["src_ip"],
                                message=alert['alert']['signature'],
                                timestamp=alert['timestamp']
                                , severity=alert['alert']['severity']
                                , category = alert['alert']['category']
                                ,
                                log_source=source
                            ))
                            source.alerts_read += 1
                            source.last_alert_index += len(line)
                        else:
                            alerts.append(IDSAlert(
                                dest_ip=alert["dest_ip"],
                                src_ip=alert["src_ip"],
                                message=alert['alert']['signature'],
                                timestamp=alert['timestamp']
                                , category = alert['alert']['category']
                                ,
                                log_source=source
                            ))
                            source.alerts_read += 1
                            source.last_alert_index += len(line)
                    elif lower_name == "wazuh":
                        try:
                            if alert.at_pointer("/data/srcip"):
                                groups=alert.at_pointer(
                                    source.alert_fields.category
                                )
                                catergory=groups
                                alerts.append(IDSAlert(
                                dest_ip=alert["dest_ip"],
                                src_ip=alert["src_ip"],
                                message=alert['alert']['signature'],
                                timestamp=alert['timestamp']
                                , severity=alert['alert']['severity']
                                , category = alert['alert']['category']
                                ,
                                log_source=source
                                ))
                                source.alerts_read += 1
                                source.last_alert_index += len(line)
                        except KeyError:
                            try:
                                if alert.at_pointer("/agent/name"):
                                    groups = alert.at_pointer(
                                        source.alert_fields.category
                                    )
                                catergory = groups
                                alerts.append(IDSAlert(
                                dest_ip=alert["dest_ip"],
                                src_ip=alert["src_ip"],
                                message=alert['alert']['signature'],
                                timestamp=alert['timestamp']
                                , severity=alert['alert']['severity']
                                , category = alert['alert']['category']
                                ,
                                log_source=source
                                ))
                                source.alerts_read += 1
                                source.last_alert_index += len(line)
                            except KeyError:
                                source.last_alert_index += 1
                    if source.alerts_read == source.max_alerts:
                        source.alerts_read = 0
                        log_file.close()
                        return alerts
                log_file.close()
                if kwargs.get("is_benchmark", None):
                    return alerts, targeted_parser
        
    targeted_parser = "cysimdjson"
    parser = cysimdjson.JSONParser()
    with open(source.log_path, "rb") as log_file:
        log_file.seek(source.last_alert_index, 0)
        for line in log_file:
            try:
                alert = parser.parse(line)
            except Exception as e:
                source.last_alert_index += len(line)
                break
            if lower_name == "suricata"\
                    and alert.at_pointer("/event_type") == "alert"\
                    or lower_name == "teler":
                source.alerts_read += 1
                source.last_alert_index += len(line)
                if hasattr(source.alert_fields, "severity") and alert.at_pointer(source.alert_fields.severity):
                    alerts.append(IDSAlert(
                        dest_ip=alert.at_pointer(
                            source.alert_fields.dest_ip),
                        src_ip=alert.at_pointer(
                            source.alert_fields.src_ip),
                        message=alert.at_pointer(
                            source.alert_fields.message),
                        timestamp=alert.at_pointer(
                            source.alert_fields.timestamp
                        ), severity=alert.at_pointer(
                            source.alert_fields.severity
                        ), category=alert.at_pointer(
                            source.alert_fields.category
                        ),
                        log_source=source
                    ))
                else:

                    alerts.append(IDSAlert(
                        dest_ip=alert.at_pointer(
                            source.alert_fields.dest_ip),
                        src_ip=alert.at_pointer(
                            source.alert_fields.src_ip),
                        message=alert.at_pointer(
                            source.alert_fields.message),
                        timestamp=alert.at_pointer(
                            source.alert_fields.timestamp
                        ),
                        category=alert.at_pointer(
                            source.alert_fields.category
                        ),
                        log_source=source
                    ))

            elif lower_name == "wazuh":
                try:
                    source.alerts_read += 1
                    source.last_alert_index += len(line)
                    if alert.at_pointer("/data/srcip"):
                        groups = alert.at_pointer(
                            source.alert_fields.category
                        )
                        catergory = groups
                        alerts.append(IDSAlert(
                            dest_ip=alert.at_pointer(
                                source.alert_fields.dest_ip),
                            src_ip=alert.at_pointer(
                                source.alert_fields.src_ip),
                            message=alert.at_pointer(
                                source.alert_fields.message),
                            timestamp=alert.at_pointer(
                                source.alert_fields.timestamp
                            ), severity=alert.at_pointer(
                                source.alert_fields.severity
                            ),
                            category=catergory,
                            log_source=source
                        ))
                except KeyError:
                    try:
                        if alert.at_pointer("/agent/name"):
                            groups = alert.at_pointer(
                                source.alert_fields.category
                            )
                        catergory = groups
                        alerts.append(IDSAlert(
                            dest_ip=alert.at_pointer(
                                source.alert_fields.dest_ip),
                            src_ip=alert.at_pointer(
                                source.alert_fields.dest_ip),
                            message=alert.at_pointer(
                                source.alert_fields.message),
                            timestamp=alert.at_pointer(
                                source.alert_fields.timestamp
                            ), severity=alert.at_pointer(
                                source.alert_fields.severity
                            ),
                            category=catergory,
                            log_source=source
                        ))
                    except KeyError:
                        source.last_alert_index += 1
            if source.alerts_read == source.max_alerts:
                source.alerts_read = 0
                log_file.close()
                return alerts, targeted_parser
    log_file.close()
    return alerts, targeted_parser
   
