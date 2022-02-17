"""
Shared utilities for both the logger and API
"""
import json
import logging

from Lib.parsers import parse_single_line_json
from json.decoder import JSONDecodeError
import yaml

from Lib.models import DictObj
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
from timeit import default_timer as timer
from datetime import timedelta

# List of IDS current supported by the system
VALID_LOG_SOURCES = ["suricata","teler","wazuh"]
# Keys that must be present in the global_options section
EXPECTED_GLOBAL_KEYS = ["api_forward_event_endpoint", "api_id_file",
                       "api_is_enabled","api_key_file","api_max_retries",
                       "api_status_endpoint","api_url","polling_rate",
                       "ssl_cert_file"]

logger = logging.getLogger(__name__)

def get_config_opts(path,**is_api_config):
    """
    Loads options from a specified config file path @returns dict of options
    also runs basic validation.
    """
    if not is_api_config:
        with open(path, "r", encoding="utf-8") as yml_file:
            opts = yaml.load(yml_file, Loader=Loader)
        # Validate Options
        test_opts = DictObj(opts)
        if not opts["global_options"] or not opts["ids_options"] or len(opts["ids_options"]) == 0:
            raise KeyError
        else:
            for key in EXPECTED_GLOBAL_KEYS:
                if not hasattr(test_opts.global_options, key):
                    raise KeyError
            if not len(EXPECTED_GLOBAL_KEYS) == len(test_opts.global_options.__dict__):
                raise KeyError
        return opts
    else:
        with open(path,"r",encoding="utf-8") as api_yml_file:
            opts = yaml.load(api_yml_file,Loader=Loader)
        return opts


def parse_logs(source):
    """
    Reads alerts from a log source and returns the latest alerts as
    alert objects.
    """
    alerts = []
    # Determine the source of the log
    if source.ids_name.lower() in VALID_LOG_SOURCES:
        try:
            if source.ids_name.lower() == "suricata" or source.ids_name.lower() == "teler" or source.ids_name.lower() == "wazuh":
                start = timer()
                alerts = parse_single_line_json(source)
                end = timer()
                logger.info("Parsed events from {} in {} secs".format(
                    source,timedelta(seconds=end-start)))
        except FileNotFoundError:
            source.is_valid = False
            logging.error("Log file - %s not found", source.log_path)
            return alerts
        except IOError:
            source.is_valid = False
            logging.error(
                "An I/O error ocurred when %s was read", source.log_path)
        except JSONDecodeError:
            source.is_valid = False
            logging.error(
                "A JSON error occured when %s was read", source.log_path)
        return alerts
    else:
        source.is_valid = False
        logging.error(
            "Tried to load from an unsupported source, %s", source.ids_name)
    return alerts

