"""
Parsers for each log file format
Reading JSON takes ages with the default module and even with some of the
'fast' third party modules. So we need to use cysimdjson
"""
from cmath import log
import logging
from os import name
from telnetlib import BRK
import cysimdjson

from Lib.models import IDSAlert


logger = logging.getLogger(__name__)


def parse_single_line_json(source):
    """
    This func handles log files that store individual alerts as valid JSON but,
    do not store alerts in a valid list and instead dump each alert 
    sequentially.
    The IDS that are currently known to follow this format are:
    1. Suricata
    2. teler
    3. wazuh
    """
    parser = cysimdjson.JSONParser()
    alerts = []
    with open(source.log_path, "rb") as log_file:
        log_file.seek(source.last_alert_index,0)
        for line in log_file:
            try:
                alert = parser.parse(line)
            except:
                source.last_alert_index += len(line)
                break
            if source.ids_name.lower() == "suricata"\
                    and alert.at_pointer("/event_type") == "alert"\
                    or source.ids_name.lower() == "teler":
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
                            ),severity=alert.at_pointer(
                                source.alert_fields.severity
                            ),category=alert.at_pointer(
                                source.alert_fields.category
                            ),
                            log_source=source
                        ))
                        source.alerts_read += 1
                        source.last_alert_index += len(line)
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
                        source.alerts_read += 1
                        source.last_alert_index += len(line)
            elif source.ids_name.lower() =="wazuh":
                try:
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
                            ),severity=alert.at_pointer(
                                source.alert_fields.severity
                            ),
                                category=catergory,
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
                            dest_ip=alert.at_pointer(
                                source.alert_fields.dest_ip),
                            src_ip=alert.at_pointer(
                                source.alert_fields.src_ip),
                            message=alert.at_pointer(
                                source.alert_fields.message),
                            timestamp=alert.at_pointer(
                                source.alert_fields.timestamp
                            ),severity=alert.at_pointer(
                                source.alert_fields.severity
                            ),
                                category=catergory,
                            log_source=source
                            ))
                        source.alerts_read += 1
                        source.last_alert_index += len(line)
                    except KeyError:
                        source.last_alert_index += 1
            if source.alerts_read  == source.max_alerts:
                source.alerts_read = 0
                log_file.close()
                return alerts
        log_file.close()
        return alerts