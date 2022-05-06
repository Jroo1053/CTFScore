import unittest
import requests
import json
from requests.sessions import Request

from werkzeug.wrappers import response

CORRECT_AUTH_JSON = {
    "id": "wZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ",
    "key": "yeZbzyJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE"
}
BAD_KEY_AUTH_JSON = {
    "id": "wZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ",
    "key": "76hdbzyJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE"
}

BAD_ID_AUTH_JSON = {
    "id": "wadaZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ",
    "key": "yeZbzyJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE"
}

BAD_BOTH_AUTH_JSON = {
    "id": "wadZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ",
    "key": "yeZadadbzyJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE"
}

MISSING_KEY_AUTH_JSON = {
    "id": "wZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ",
}

FORWARD_EVENTS_CORRECT_JSON ="""{"py/object": "Lib.models.APIRequest", "request_content": "[[{\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"67.219.148.138\\", \\"src_ip\\": \\"172.200.0.50\\", \\"message\\": \\"ET POLICY GNU/Linux YUM User-Agent Outbound likely related to package management\\", \\"timestamp\\": \\"2022-03-15T09:16:02.328867+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Suricata\\", \\"log_path\\": \\"./logconf/eve.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/dest_ip\\", \\"src_ip\\": \\"/src_ip\\", \\"message\\": \\"/alert/signature\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/alert/category\\", \\"severity\\": \\"/alert/severity\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 225791, \\"alerts_read\\": 0, \\"reliability\\": 5, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"Unknown Classtype\\", \\"severity\\": 3}, {\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"192.168.56.1\\", \\"src_ip\\": \\"172.200.0.30\\", \\"message\\": \\"SURICATA HTTP unable to match response to request\\", \\"timestamp\\": \\"2022-03-15T09:16:46.094226+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Suricata\\", \\"log_path\\": \\"./logconf/eve.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/dest_ip\\", \\"src_ip\\": \\"/src_ip\\", \\"message\\": \\"/alert/signature\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/alert/category\\", \\"severity\\": \\"/alert/severity\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 225791, \\"alerts_read\\": 0, \\"reliability\\": 5, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"Unknown Classtype\\", \\"severity\\": 3}], [{\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"apachesite\\", \\"src_ip\\": \\"apachesite\\", \\"message\\": \\"SCA summary: CIS Benchmark for Debian/Linux 10: Score less than 50% (38)\\", \\"timestamp\\": \\"2022-03-17T08:57:01.113+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Wazuh\\", \\"log_path\\": \\"./logconf/alerts.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/agent/name\\", \\"src_ip\\": \\"/data/srcip\\", \\"message\\": \\"/rule/description\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/rule/groups/0\\", \\"severity\\": \\"/rule/level\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 2713, \\"alerts_read\\": 0, \\"reliability\\": 8, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"sca\\", \\"severity\\": 7}, {\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"dockerhost\\", \\"src_ip\\": \\"dockerhost\\", \\"message\\": \\"CIS Benchmark for Debian/Linux 10: Ensure updates, patches, and additional security software are installed: Status changed from failed to passed\\", \\"timestamp\\": \\"2022-03-17T08:57:06.269+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Wazuh\\", \\"log_path\\": \\"./logconf/alerts.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/agent/name\\", \\"src_ip\\": \\"/data/srcip\\", \\"message\\": \\"/rule/description\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/rule/groups/0\\", \\"severity\\": \\"/rule/level\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 2713, \\"alerts_read\\": 0, \\"reliability\\": 8, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"sca\\", \\"severity\\": 3}]]", "key": "ab7363b1afdc3103ebb90dcfa27863c596c54b36033f207fe7aa2215a92cd3819d205d139b2451d690ee38320b0e046d31dde5ac1d64d50c2c41eae083eb5a4ac161a4215b9662b9cce491dba781a830a4118e90f0c2d90d983b74b514529fbcc96696fb294ae815f3fdb09b46dac8c6093d550d7fbf09beae7feb7349b62ab7", "id": "f93ecef1ac62477f8bcde8e4745dd947b2d8fe0c1766e901d7a03092cc68b2a45592a7de39a3b35d1a9e7573a587ab2caff7d352e911b11ff9ec3c3d50bdf6a3"}"""

FORWARD_EVENTS_BAD_VALS_JSON = """{
    "py/object": "Lib.models.APIRequest",
    "json": [
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "192.168.56.107",
                "src_ip": "192.168.56.1",
                "message": "ET SCAN Possible Nmap User-Agent Observed",
                "timestamp": "2021-11-02T16: 18: 47.321549+0000",
                "log_source": {
                    "py/object": "Lib.models.LogSource",
                    "ids_name": "Suricata",
                    "log_path": "Source/Test/Files/bigeve.json",
                    "is_valid": true,
                    "alerts": [],
                    "alert_fields": {
                        "py/object": "Lib.models.AlertFields",
                        "dest_ip": "/dest_ip",
                        "src_ip": "/src_ip",
                        "message": "/alert/signature",
                        "timestamp": "/timestamp",
                        "category": "/alert/category",
                        "severity": "/alert/severity"
                    },
                    "max_alerts": 1,
                    "last_alert_index": 3,
                    "alerts_read": 0,
                    "reliability": 50
                },
                "category": "Web Application Attack",
                "severity": 1
            }
        ],
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "wazuh-manager",
                "src_ip": "192.168.56.1",
                "message": "sshd: authentication success.",
                "timestamp": "2021-11-15T15: 41: 45.451+0000",
                "log_source": {
                    "py/object": "Lib.models.LogSource",
                    "ids_name": "Wazuh",
                    "log_path": "Source/Test/Files/wazuh.json",
                    "is_valid": true,
                    "alerts": [],
                    "alert_fields": {
                        "py/object": "Lib.models.AlertFields",
                        "dest_ip": "/agent/name",
                        "src_ip": "/data/srcip",
                        "message": "/rule/description",
                        "timestamp": "/timestamp",
                        "category": "/rule/groups/0",
                        "severity": "/rule/level"
                    },
                    "max_alerts": 1,
                    "last_alert_index": 3,
                    "alerts_read": 0,
                    "reliability": 80
                },
                "category": "syslog",
                "severity": "3"
            }
        ]
    ],
    "key": "yeZbzyJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE",
    "id": "wZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ"
}"""

FORWARD_EVENTS_NO_AUTH_JSON = """{
    "py/object": "Lib.models.APIRequest",
    "json": [
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "192.168.56.107",
                "src_ip": "192.168.56.1",
                "message": "ET SCAN Possible Nmap User-Agent Observed",
                "timestamp": "2021-11-02T16:18:47.321549+0000",
                "log_source": {
                    "py/object": "Lib.models.LogSource",
                    "ids_name": "Suricata",
                    "log_path": "Source/Test/Files/bigeve.json",
                    "is_valid": true,
                    "alerts": [],
                    "alert_fields": {
                        "py/object": "Lib.models.AlertFields",
                        "dest_ip": "/dest_ip",
                        "src_ip": "/src_ip",
                        "message": "/alert/signature",
                        "timestamp": "/timestamp",
                        "category": "/alert/category",
                        "severity": "/alert/severity"
                    },
                    "max_alerts": 1,
                    "last_alert_index": 3,
                    "alerts_read": 0,
                    "reliability": 50
                },
                "category": "Web Application Attack",
                "severity": 1
            }
        ],
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "wazuh-manager",
                "src_ip": "192.168.56.1",
                "message": "sshd: authentication success.",
                "timestamp": "2021-11-15T15:41:45.451+0000",
                "log_source": {
                    "py/object": "Lib.models.LogSource",
                    "ids_name": "Wazuh",
                    "log_path": "Source/Test/Files/wazuh.json",
                    "is_valid": true,
                    "alerts": [],
                    "alert_fields": {
                        "py/object": "Lib.models.AlertFields",
                        "dest_ip": "/agent/name",
                        "src_ip": "/data/srcip",
                        "message": "/rule/description",
                        "timestamp": "/timestamp",
                        "category": "/rule/groups/0",
                        "severity": "/rule/level"
                    },
                    "max_alerts": 1,
                    "last_alert_index": 3,
                    "alerts_read": 0,
                    "reliability": 80
                },
                "category": "syslog",
                "severity": 3
            }
        ]
    ]
}"""

FORWARD_EVENTS_BAD_AUTH_JSON = """{
    "py/object": "Lib.models.APIRequest",
    "json": [
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "192.168.56.107",
                "src_ip": "192.168.56.1",
                "message": "ET SCAN Possible Nmap User-Agent Observed",
                "timestamp": "2021-11-02T16:18:47.321549+0000",
                "log_source": {
                    "py/object": "Lib.models.LogSource",
                    "ids_name": "Suricata",
                    "log_path": "Source/Test/Files/bigeve.json",
                    "is_valid": true,
                    "alerts": [],
                    "alert_fields": {
                        "py/object": "Lib.models.AlertFields",
                        "dest_ip": "/dest_ip",
                        "src_ip": "/src_ip",
                        "message": "/alert/signature",
                        "timestamp": "/timestamp",
                        "category": "/alert/category",
                        "severity": "/alert/severity"
                    },
                    "max_alerts": 1,
                    "last_alert_index": 3,
                    "alerts_read": 0,
                    "reliability": 50
                },
                "category": "Web Application Attack",
                "severity": 1
            }
        ],
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "wazuh-manager",
                "src_ip": "192.168.56.1",
                "message": "sshd: authentication success.",
                "timestamp": "2021-11-15T15:41:45.451+0000",
                "log_source": {
                    "py/object": "Lib.models.LogSource",
                    "ids_name": "Wazuh",
                    "log_path": "Source/Test/Files/wazuh.json",
                    "is_valid": true,
                    "alerts": [],
                    "alert_fields": {
                        "py/object": "Lib.models.AlertFields",
                        "dest_ip": "/agent/name",
                        "src_ip": "/data/srcip",
                        "message": "/rule/description",
                        "timestamp": "/timestamp",
                        "category": "/rule/groups/0",
                        "severity": "/rule/level"
                    },
                    "max_alerts": 1,
                    "last_alert_index": 3,
                    "alerts_read": 0,
                    "reliability": 80
                },
                "category": "syslog",
                "severity": 3
            }
        ]
    ],
    "key": "yeZbzdadayJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE",
    "id": "wZ3SeadHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ"
}"""

FORWARD_EVENTS_SINGLE_JSON = """{"py/object": "Lib.models.APIRequest", "request_content": "[[{\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"67.219.148.138\\", \\"src_ip\\": \\"172.200.0.50\\", \\"message\\": \\"ET POLICY GNU/Linux YUM User-Agent Outbound likely related to package management\\", \\"timestamp\\": \\"2022-03-15T09:16:02.328867+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Suricata\\", \\"log_path\\": \\"./logconf/eve.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/dest_ip\\", \\"src_ip\\": \\"/src_ip\\", \\"message\\": \\"/alert/signature\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/alert/category\\", \\"severity\\": \\"/alert/severity\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 225791, \\"alerts_read\\": 0, \\"reliability\\": 5, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"Unknown Classtype\\", \\"severity\\": 3}, {\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"192.168.56.1\\", \\"src_ip\\": \\"172.200.0.30\\", \\"message\\": \\"SURICATA HTTP unable to match response to request\\", \\"timestamp\\": \\"2022-03-15T09:16:46.094226+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Suricata\\", \\"log_path\\": \\"./logconf/eve.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/dest_ip\\", \\"src_ip\\": \\"/src_ip\\", \\"message\\": \\"/alert/signature\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/alert/category\\", \\"severity\\": \\"/alert/severity\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 225791, \\"alerts_read\\": 0, \\"reliability\\": 5, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"Unknown Classtype\\", \\"severity\\": 3}], [{\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"apachesite\\", \\"src_ip\\": \\"apachesite\\", \\"message\\": \\"SCA summary: CIS Benchmark for Debian/Linux 10: Score less than 50% (38)\\", \\"timestamp\\": \\"2022-03-17T08:57:01.113+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Wazuh\\", \\"log_path\\": \\"./logconf/alerts.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/agent/name\\", \\"src_ip\\": \\"/data/srcip\\", \\"message\\": \\"/rule/description\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/rule/groups/0\\", \\"severity\\": \\"/rule/level\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 2713, \\"alerts_read\\": 0, \\"reliability\\": 8, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"sca\\", \\"severity\\": 7}, {\\"py/object\\": \\"Lib.models.IDSAlert\\", \\"dest_ip\\": \\"dockerhost\\", \\"src_ip\\": \\"dockerhost\\", \\"message\\": \\"CIS Benchmark for Debian/Linux 10: Ensure updates, patches, and additional security software are installed: Status changed from failed to passed\\", \\"timestamp\\": \\"2022-03-17T08:57:06.269+0000\\", \\"log_source\\": {\\"py/object\\": \\"Lib.models.LogSource\\", \\"ids_name\\": \\"Wazuh\\", \\"log_path\\": \\"./logconf/alerts.json\\", \\"is_valid\\": true, \\"alerts\\": [], \\"alert_fields\\": {\\"py/object\\": \\"Lib.models.AlertFields\\", \\"dest_ip\\": \\"/agent/name\\", \\"src_ip\\": \\"/data/srcip\\", \\"message\\": \\"/rule/description\\", \\"timestamp\\": \\"/timestamp\\", \\"category\\": \\"/rule/groups/0\\", \\"severity\\": \\"/rule/level\\"}, \\"max_alerts\\": 2, \\"last_alert_index\\": 2713, \\"alerts_read\\": 0, \\"reliability\\": 8, \\"last_alert_timestamp\\": \\"\\", \\"last_alert_message\\": \\"\\"}, \\"category\\": \\"sca\\", \\"severity\\": 3}]]", "key": "ab7363b1afdc3103ebb90dcfa27863c596c54b36033f207fe7aa2215a92cd3819d205d139b2451d690ee38320b0e046d31dde5ac1d64d50c2c41eae083eb5a4ac161a4215b9662b9cce491dba781a830a4118e90f0c2d90d983b74b514529fbcc96696fb294ae815f3fdb09b46dac8c6093d550d7fbf09beae7feb7349b62ab7", "id": "f93ecef1ac62477f8bcde8e4745dd947b2d8fe0c1766e901d7a03092cc68b2a45592a7de39a3b35d1a9e7573a587ab2caff7d352e911b11ff9ec3c3d50bdf6a3"}"""
API_TARGET_URL = "http://localhost:5000/api/"


class TestAPIAuth(unittest.TestCase):

    def test_correct_credentials(self):
        response = requests.post(url=(API_TARGET_URL + "verifyauth"),
                                 json=json.dumps(CORRECT_AUTH_JSON))
        assert response.status_code == 200

    def test_incorrect_key(self):
        response = requests.post(url=(API_TARGET_URL + "verifyauth"),
                                 json=json.dumps(BAD_KEY_AUTH_JSON))
        assert response.status_code == 403

    def test_incorrect_id(self):
        response = requests.post(url=(API_TARGET_URL + "verifyauth"),
                                 json=json.dumps(BAD_ID_AUTH_JSON))
        assert response.status_code == 403

    def test_incorrect_both(self):
        response = requests.post(url=(API_TARGET_URL + "verifyauth"),
                                 json=json.dumps(BAD_BOTH_AUTH_JSON))
        assert response.status_code == 403

    def test_missing_key(self):
        response = requests.post(url=(API_TARGET_URL + "verifyauth"),
                                 json=json.dumps(MISSING_KEY_AUTH_JSON))
        assert response.status_code == 400


class TestAPIForwardEvents(unittest.TestCase):

    def test_forward_events_correct(self):
        response = requests.post(url=(API_TARGET_URL + "/events"),
                                 json=FORWARD_EVENTS_CORRECT_JSON)
        assert response.status_code == 200

    def test_forward_events_no_auth(self):
        response = requests.post(url=(API_TARGET_URL + "/events"),
                                 json=FORWARD_EVENTS_NO_AUTH_JSON)
        assert response.status_code == 400

    def test_forward_events_bad_auth(self):
        response = requests.post(url=(API_TARGET_URL + "/events"),
                                 json=FORWARD_EVENTS_BAD_AUTH_JSON)
        assert response.status_code == 403

    def test_forward_events_bad_vals(self):
        response = requests.post(url=(API_TARGET_URL + "/events"),
                                 json=FORWARD_EVENTS_BAD_VALS_JSON)
        assert response.status_code == 500

    def test_forward_events_single(self):
        response = requests.post(url=(API_TARGET_URL + "/events"),
                                 json=FORWARD_EVENTS_SINGLE_JSON)
        assert response.status_code == 200


class TestAPIGetStatus(unittest.TestCase):

    def test_get_status_working(self):
        response = requests.get(url=(API_TARGET_URL + "status"))
        assert response.status_code == 200

    def test_get_status_bad_request(self):
        response = requests.post(url=(API_TARGET_URL + "status"))
        assert response.status_code == 405



if __name__ == "__main__":
    unittest.main()
