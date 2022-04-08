"""
Parsers for each log file format
Reading JSON takes ages with the default module and even with some of the
'fast' third party modules. So we need to use cysimdjson this also simplifies
setting the JSON fields in the config file.
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
    """
    _summary_: Parse events from a source that stores alerts as seprate JSON 
    objects with, each alert taking exactly one line. This appears to be used
    by most if not all IDS. 
    Args:
        source (LogSource): Log Source To Read
        **is_randjson(bool): A random parser will be used  when this is set. 
        Usefull when used alongside the bencharking mode (-b)
    Returns:
        alerts ([IDSAlert]): A list containing the alerts stored as IDSAlert 
        objects
        parser (string): The parser used to perform parse the alerts this
        time around. This defaults to cysmidjson. 
    """
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
    """
    _summary_: Create an alert from from a given line using, a source, and 
    parser
    Args:
        source (LogSource): Log source that originally produced the alert. This
        is needed to retrieve the alert fields which, are set in the config file
        and allow the system to adapat to different IDS logging formats.
        lower_name (string): The name of the IDS in lowercase used, to match
        sources and minimise CPU time spent converting cases
        line: line of JSON to read from
        parser: JSON parser to translate alert 
    Returns:
        alert (IDSAlert): If successful will return the the IDS alert as a python
        object
        parser (string): Returns the name of the parser used to produce the alert.
    """
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
                # Suricata has a convenient alert_type field that lets us ignore different entires 
                if suricata_alert_type == 'alert'\
                     and hasattr(source.alert_fields,"severity") and alert.at_pointer(source.alert_fields.severity):
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
                        # If the alert has a source IP it can be treated as normal
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
                    Naturally, IDS alerts that do not invole network activity 
                    will not contain a source ip. To resolve this issue we,
                    we set the the dest and source ip the the name of the agent
                    """
                    try:
                        if alert.at_pointer("/agent/name"):
                            groups = alert.at_pointer(
                                source.alert_fields.category
                            )
                        catergory = groups
                        return IDSAlert(
                            dest_ip=alert.at_pointer("/agent/name"),
                            src_ip=alert.at_pointer("/agent/name"),
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
