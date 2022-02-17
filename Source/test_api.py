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

FORWARD_EVENTS_CORRECT_JSON = """{
    "py/object": "Lib.models.APIRequest",
    "json": [
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "192.168.56.107",
                "src_ip": "192.168.56.1",
                "message": "ET SCAN Possible Nmap User-Agent Observed",
                "timestamp": "2021-11-02T16:18:47.321272+0000",
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
                    "last_alert_index": 5,
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
                    "last_alert_index": 5,
                    "alerts_read": 0,
                    "reliability": 80
                },
                "category": "syslog",
                "severity": 3
            }
        ]
    ],
    "key": "yeZbzyJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE",
    "id": "wZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ"
}"""

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

FORWARD_EVENTS_SINGLE_JSON = """{
    "py/object": "Lib.models.APIRequest",
    "json": [
        [
            {
                "py/object": "Lib.models.IDSAlert",
                "dest_ip": "192.168.56.107",
                "src_ip": "192.168.56.1",
                "message": "ET SCAN Possible Nmap User-Agent Observed",
                "timestamp": "2021-11-02T16:18:47.321272+0000",
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
                    "last_alert_index": 5,
                    "alerts_read": 0,
                    "reliability": 50
                },
                "category": "Web Application Attack",
                "severity": 1
            }
        ]
    ],
    "key": "yeZbzyJk0x45YCN-y756JAuCC6oaEwtM6gHpKXUNc0HR9fR5YgKQgvtGQQ2O7SaoTubleBDkVXBtYO9iVtqgUHHXkoBaJjQc23fCE-FmxYdRIILznK7e_nckTQ8i-VvgQMsKlh1S-RqcMAqDlIKo6ezxiOHApXDI5xbjsSpXb9Drz7S1Z0SoN6869Vj-Zr2kR5OuhIq2KquJpN4aC7yQS1-zJpL0sAolg7vagzZf6WyucvBe6q7_JCD2QmVoYylE",
    "id": "wZ3SeHyPz9Qe0_mzXUW2-rq_9g6o4KP5oHIZbqt7REHEKrjCtJprDq7m8oozATVt_6SSWeE1bKsD9S5X9awW-fm2SCzS6Dhr5ZwQ7syw7vJE1uOaYtL9bIUHEdbA-KQJ"
}"""
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
        assert response.status_code == 400

    def test_forward_events_single(self):
        response = requests.post(url=(API_TARGET_URL + "/events"),
                                 json=FORWARD_EVENTS_SINGLE_JSON)
        assert response.status_code == 200


class TestAPIGetStatus(unittest.TestCase):

    def test_get_status_working(self):
        response = requests.get(url=API_TARGET_URL)
        assert response.status_code == 200

    def test_get_status_bad_request(self):
        response = requests.post(url=API_TARGET_URL)
        assert response.status_code == 405


if __name__ == "__main__":
    unittest.main()
