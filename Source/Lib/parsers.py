"""
Parsers for each log file format
Reading JSON takes ages with the default module and even with some of the
'fast' third party modules. So we need to use cysimdjson
"""

import cysimdjson
import json

import random
import jsonpickle

import orjson
import ujson

from Lib.models import IDSAlert

SUPPORTED_JSON_PARSERS = ["json", "cysimdjson",
                          "orjson", "ujson", "jsonpickle"]


def parse_single_line_json(source, **kwargs):
    alerts = []
    parser = ""
    source_name = source.ids_name.lower()
    if kwargs.get("is_rand_json", None):
        parser = random.choice(SUPPORTED_JSON_PARSERS)
        with open(source.log_path, "rb") as log_file:
            log_file.seek(source.last_alert_index, 0)
            for line in log_file:
                if source.alerts_read != source.max_alerts:
                    alert, parser = create_alert(source, source_name, line,
                                                 parser=parser)
                    source.last_alert_index += len(line)
                    if alert:
                        alerts.append(alert)
                        source.alerts_read += 1
            log_file.close()
    else:
        with open(source.log_path, "rb") as log_file:
            parser = "cysimdjson"
            log_file.seek(source.last_alert_index, 0)
            for line in log_file:
                if source.alerts_read != source.max_alerts:
                    alert, parser = create_alert(
                        source, source_name, line, parser=parser)
                    source.last_alert_index += len(line)
                    if alert:
                        alerts.append(alert)
                        source.alerts_read += 1
            log_file.close()
    source.alerts_read = 0
    return alerts, parser


def create_alert(source, lower_name, line, parser):
    try:
        if parser == "cysimdjson":
            json_parser = cysimdjson.JSONParser()
            try:
                alert = json_parser.parse(line)
            except Exception as e:
                logger.info("%s failed to parse %s", parser, line)
                return False, parser
            if lower_name == "suricata":
                suricata_alert_type = alert.at_pointer("/event_type")
                if suricata_alert_type == 'alert' and hasattr(source.alert_fields, "severity") and alert.at_pointer(source.alert_fields.severity):
                    return IDSAlert(
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
                    ), parser
            elif lower_name == "wazuh":
                try:
                    if alert.at_pointer("/data/srcip"):
                        groups = alert.at_pointer(
                            source.alert_fields.category
                        )
                        catergory = groups
                        return IDSAlert(
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
                        ), parser
                except KeyError:
                    """
                    Only some of the Wazuh alerts include a source ip,
                    if this line doesn't contain one create an alert but,
                    set the dest and src to the same values.   
                    """
                    try:
                        if alert.at_pointer("/agent/name"):
                            groups = alert.at_pointer(
                                source.alert_fields.category
                            )
                        catergory = groups
                        return IDSAlert(
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
                        ), parser
                    except Exception as e:
                        return False, parser
            return False, parser
        elif parser == "json":
            alert = json.loads(line)
        elif parser == "orjson":
            alert = orjson.loads(line)
        elif parser == "ujson":
            alert = ujson.loads(line)
        elif parser == "jsonpickle":
            alert = jsonpickle.loads(line)
        if lower_name == "suricata" and alert["event_type"] == "alert"\
                or lower_name == "teler":
            if alert['alert']['severity']:
                return IDSAlert(
                    dest_ip=alert["dest_ip"],
                    src_ip=alert["src_ip"],
                    message=alert['alert']['signature'],
                    timestamp=alert['timestamp'], severity=alert['alert']['severity'], category=alert['alert']['category'],
                    log_source=source
                ), parser
            else:
                return IDSAlert(
                    dest_ip=alert["dest_ip"],
                    src_ip=alert["src_ip"],
                    message=alert['alert']['signature'],
                    timestamp=alert['timestamp'], category=alert['alert']['category'],
                    log_source=source
                ), parser
        elif lower_name == "wazuh":
            try:
                if alert.event_type == "alert":
                    groups = alert.at_pointer(
                        source.alert_fields.category
                    )
                    catergory = groups

                    return IDSAlert(
                        dest_ip=alert["dest_ip"],
                        src_ip=alert["src_ip"],
                        message=alert['alert']['signature'],
                        timestamp=alert['timestamp'], severity=alert['alert'][
                            'severity'], category=alert['alert']['category'],
                        log_source=source
                    ), parser

            except KeyError:
                try:
                    if alert.at_pointer("/agent/name"):
                        groups = alert.at_pointer(
                            source.alert_fields.category
                        )
                    catergory = groups
                    return IDSAlert(
                        dest_ip=alert["dest_ip"],
                        src_ip=alert["src_ip"],
                        message=alert['alert']['signature'],
                        timestamp=alert['timestamp'], severity=alert['alert'][
                            'severity'], category=alert['alert']['category'],
                        log_source=source
                    ), parser
                except Exception as e:
                    return False, parser
        return False, parser
    except Exception as e:
        return False, parser
