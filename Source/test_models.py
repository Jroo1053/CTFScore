import datetime
from Source.Lib.models import *
import unittest
from pytest_httpserver.httpserver import HTTPServer


class TestApiConnection(unittest.TestCase):

    def test_init_connection_valid(self):
        """
        Checks if it is possible to create the api connection object without 
        error, if presented with valid options
        """
        try:
            init_api = APIConnection("Localhost", 100,
                                     "/etc/ctfscorelog/api_id.txt",
                                     "/etc/ctfscorelog/api_key.txt",
                                     "/status", "/events",
                                     5, True)
            self.assertTrue(True)
        except FileNotFoundError:
            print("The api key or id file was not found ")
            self.assertTrue(False)
        except IOError:
            print(
                "A file IO error occurred when reading the api key or id file")
            self.assertTrue(False)
        except ValueError as api_error:
            print(("The api %s are invalid, exiting! ", api_error.args))
            self.assertTrue(False)

    def test_init_connection_no_keys(self):
        """
        Checks if the api_connection object fails when provided with no creds,
        Note that it should fail in the right way
        """
        try:
            init_api = APIConnection("Localhost", 100,
                                     "/thisisnotarealpath/adadad.txt",
                                     "/anothernotrealpath/oof.txt",
                                     "/status", "/events",
                                     5, True)
            self.assertTrue(False)
        except FileNotFoundError:
            print("The api key or id file was not found ")
            self.assertTrue(True)
        except IOError:
            print(
                "A file IO error occurred when reading the api key or id file")
            self.assertTrue(False)
        except ValueError as api_error:
            print(("The api %s are invalid, exiting! ", api_error.args))
            self.assertTrue(False)

    def test_init_connection_invalid_key(self):
        """
        Checks if the api_connection object fails when provided with a
        key file that should fail the validation check
        """
        try:
            init_api = APIConnection("Localhost", 100,
                                     "/etc/ctfscorelog/api_id.txt",
                                     "/etc/ctfscorelog/api_key_invalid.txt",
                                     "/status", "/events",
                                     5, True)
            self.assertTrue(False)
        except FileNotFoundError:
            print("The api key or id file was not found ")
            self.assertTrue(False)
        except IOError:
            print(
                "A file IO error occurred when reading the api key or id file")
            self.assertTrue(False)
        except ValueError as api_error:
            print(("The api %s are invalid, exiting! ", api_error.args))
            self.assertTrue(True)

    def test_init_connection_invalid_id(self):
        """
        Checks if the api_connection object fails when provided with a
        id file that should fail the validation check
        """
        try:
            init_api = APIConnection("Localhost", 100,
                                     "/etc/ctfscorelog/api_id_invalid.txt",
                                     "/etc/ctfscorelog/api_key.txt",
                                     "/status", "/events",
                                     5, True)
            self.assertTrue(False)
        except FileNotFoundError:
            print("The api key or id file was not found ")
            self.assertTrue(False)
        except IOError:
            print(
                "A file IO error occurred when reading the api key or id file")
            self.assertTrue(False)
        except ValueError as api_error:
            print(("The api %s are invalid, exiting! ", api_error.args))
            self.assertTrue(True)

    def test_init_connection_invalid_both(self):
        """
        Checks if the api_connection object fails when provided with
        files that should fail the validation check
        """
        try:
            init_api = APIConnection("Localhost", 100,
                                     "/etc/ctfscorelog/api_id_invalid.txt",
                                     "/etc/ctfscorelog/api_key_invalid.txt",
                                     "/status", "/events",
                                     5, True)
            self.assertTrue(False)
        except FileNotFoundError:
            print("The api key or id file was not found ")
            self.assertTrue(False)
        except IOError:
            print(
                "A file IO error occurred when reading the api key or id file")
            self.assertTrue(False)
        except ValueError as api_error:
            print(("The api %s are invalid, exiting! ", api_error.args))
            self.assertTrue(True)

    def test_get_api_status_true(self):
        """
        Checks the get_status function works as intended when connecting to a 
        working endpoint.
        """
        local_url = "http://127.0.0.1"
        local_port = 8979
        with HTTPServer(host="127.0.0.1", port=local_port) as test_server:
            try:
                test_server.expect_request("/status", method="GET")\
                    .respond_with_json({"api_version": "V1.0"})
                status_api = APIConnection((local_url + ":" + str(local_port)), 100,
                                           "/etc/ctfscorelog/api_id.txt",
                                           "/etc/ctfscorelog/api_key.txt",
                                           "/status", "/events",
                                           5, True)
                if status_api.get_api_status():
                    self.assertTrue(True)
                else:
                    self.assertTrue(False)
            except HTTPError as http_error:
                print((
                    "The following http error has occurred: %s", http_error.args))
                self.assertTrue(False)
            except ConnectionError as connect_error:
                print((
                    "The following connection error has occurred: %s",
                    connect_error.args
                ))
                self.assertTrue(False)

    def test_get_api_status_false(self):
        """
        Checks the get_status function works as intended when connecting to a 
        non functional endpoint
        """
        local_url = "http://127.0.0.1"
        local_port = 8980
        with HTTPServer(host="127.0.0.1", port=local_port) as test_server:
            try:
                test_server.expect_request("/status", method="GET")\
                    .respond_with_data(status=500)
                status_api = APIConnection((local_url + ":" + str(local_port)), 100,
                                           "/etc/ctfscorelog/api_id.txt",
                                           "/etc/ctfscorelog/api_key.txt",
                                           "/status", "/events",
                                           5, True)
                if status_api.get_api_status():
                    self.assertTrue(False)
                else:
                    self.assertTrue(True)
            except HTTPError as http_error:
                print((
                    "The following http error has occurred: %s", http_error.args))
                self.assertTrue(False)
            except ConnectionError as connect_error:
                print((
                    "The following connection error has occurred: %s",
                    connect_error.args
                ))
                self.assertTrue(False)

    def test_get_api_status_no_api(self):
        """
        Checks the get_status function works as intended when trying to connect
        to an url that does not respond
        """
        local_url = "http://127.0.0.1"
        local_port = 8980
        try:
            status_api = APIConnection((local_url + ":" + str(local_port)), 100,
                                       "/etc/ctfscorelog/api_id.txt",
                                       "/etc/ctfscorelog/api_key.txt",
                                       "/status", "/events",
                                       5, True)
            if status_api.get_api_status():
                self.assertTrue(False)
            else:
                self.assertTrue(True)
        except HTTPError as http_error:
            print((
                "The following http error has occurred: %s", http_error.args))
            self.assertTrue(False)
        except (requests.ConnectionError, requests.ConnectTimeout) as connect_error:
            print((
                "The following connection error has occurred: %s",
                connect_error.args
            ))
            self.assertTrue(False)

    def test_forward_IDS_alerts_no_api(self):
        """
        Checks if the forward_alerts func responds correctly if an api is not 
        present
        """
        local_url = "http://127.0.0.1"
        local_port = 8980
        alerts = []
        # Generate Sample Alerts
        for x in range(0, 200):
            alerts.append(IDSAlert(
                dest_ip="192.168.56.107",
                src_ip="192.168.56.1",
                message="Possible Nmap User-Agent Observed",
                timestamp=datetime.datetime.now(),
                log_source="Suricata",
                category="Web Application Attack",
                severity=1
            ))
        try:
            status_api = APIConnection((local_url + ":" + str(local_port)), 100,
                                       "/etc/ctfscorelog/api_id.txt",
                                       "/etc/ctfscorelog/api_key.txt",
                                       "/status", "/events",
                                       5, True)
            if status_api.forward_IDS_alerts(alerts):
                self.assertTrue(False)
            else:
                self.assertTrue(True)
        except HTTPError as http_error:
            print((
                "The following http error has occurred: %s", http_error.args))
            self.assertTrue(False)
        except ConnectionError as connect_error:
            print((
                "The following connection error has occurred: %s",
                connect_error.args
            ))
            self.assertTrue(False)

    def test_forward_ids_alerts_broken_api(self):
        """
        Checks if the forward_alerts func responds correctly if an api is not 
        working but present
        """
        local_url = "http://127.0.0.1"
        local_port = 8980
        alerts = []
        # Generate Sample Alerts
        for x in range(0, 200):
            alerts.append(IDSAlert(
                dest_ip="192.168.56.107",
                src_ip="192.168.56.1",
                message="Possible Nmap User-Agent Observed",
                timestamp=datetime.datetime.now(),
                log_source="Suricata",
                category="Web Application Attack",
                severity=1
            ))
        with HTTPServer(host="127.0.0.1", port=local_port) as test_server:
            try:
                test_server.expect_request("/events", method="POST")\
                    .respond_with_data(status=500)
                status_api = APIConnection((local_url + ":" + str(local_port)), 100,
                                           "/etc/ctfscorelog/api_id.txt",
                                           "/etc/ctfscorelog/api_key.txt",
                                           "/status", "/events",
                                           5, True)
                if status_api.forward_IDS_alerts(alerts):
                    self.assertTrue(False)
                else:
                    self.assertTrue(True)
            except HTTPError as http_error:
                print((
                    "The following http error has occurred: %s", http_error.args))
                self.assertTrue(False)
            except ConnectionError as connect_error:
                print((
                    "The following connection error has occurred: %s",
                    connect_error.args
                ))
                self.assertTrue(False)

    def test_forward_ids_alerts_working_api(self):
        """
        Checks if the forward_alerts func responds correctly if an api is 
        working and valid alerts are sent
        """
        local_url = "http://127.0.0.1"
        local_port = 8980
        alerts = []
        # Generate Sample Alerts
        for x in range(0, 200):
            alerts.append(IDSAlert(
                dest_ip="192.168.56.107",
                src_ip="192.168.56.1",
                message="Possible Nmap User-Agent Observed",
                timestamp=datetime.datetime.now(),
                log_source="Suricata",
                category="Web Application Attack",
                severity=1
            ))
        with HTTPServer(host="127.0.0.1", port=local_port) as test_server:
            try:
                test_server.expect_request("/events", method="POST",
                                           json=jsonpickle.encode(alerts))\
                    .respond_with_json({"Received": "True"})
                status_api = APIConnection((local_url + ":" + str(local_port)), 100,
                                           "/etc/ctfscorelog/api_id.txt",
                                           "/etc/ctfscorelog/api_key.txt",
                                           "/status", "/events",
                                           5, True)
                if status_api.forward_IDS_alerts(alerts):
                    self.assertTrue(True)
                else:
                    self.assertTrue(False)
            except HTTPError as http_error:
                print((
                    "The following http error has occurred: %s", http_error.args))
                self.assertTrue(False)
            except ConnectionError as connect_error:
                print((
                    "The following connection error has occurred: %s",
                    connect_error.args
                ))
                self.assertTrue(False)

    def test_api_file_matches(self):
        """
        Check if the api ID/key var produces the right result when compared to
        its input.
        """

        try:
            key_api = APIConnection("Localhost", 100,
                                    "/etc/ctfscorelog/api_id.txt",
                                    "/etc/ctfscorelog/api_key.txt",
                                    "/status", "/events",
                                    5, True)
            with open("/etc/ctfscorelog/api_id.txt", "r") as id_file:
                self.assertEquals(key_api.id, id_file.readline())
            with open("/etc/ctfscorelog/api_key.txt") as key_file:
                self.assertEquals(key_api.key, key_file.readline())
        except FileNotFoundError:
            print("The api key or id file was not found ")
            self.assertTrue(False)
        except IOError:
            print(
                "A file IO error occurred when reading the api key or id file")
            self.assertTrue(False)
        except ValueError as api_error:
            print(("The api %s are invalid, exiting! ", api_error.args))
            self.assertTrue(False)


class TestLogSourceObject(unittest.TestCase):

    def test_log_source_no_severity(self):
        test_source = LogSource(
            "Suricata",
            "Test/Files/bigeve.json",
            20,
            AlertFields(
                "\dest_ip",
                "\src_ip",
                "\message",
                "\timestamp",
                "\category",
            ),
            80
        )
        if not hasattr(test_source.alert_fields, "severity"):
            self.assertTrue(True)
        else:
            self.assertTrue(False)

    def test_log_source_with_severity(self):
        test_source = LogSource(
            "Suricata",
            "Test/Files/bigeve.json",
            20,
            AlertFields(
                "\\dest_ip",
                "\\src_ip",
                "\\message",
                "\\timestamp",
                "\\category",
                severity="\\severity"
            ),
            80
        )
        if hasattr(test_source.alert_fields, "severity"):
            self.assertTrue(True)
        else:
            self.assertTrue(False)

    def test_log_source_str(self):
        test_source = LogSource(
            "Suricata",
            "Test/Files/bigeve.json",
            20,
            AlertFields(
                "\dest_ip",
                "\src_ip",
                "\message",
                "\timestamp",
                "\category",
            ),
            80
        )
        self.assertEqual(str(test_source), "Suricata,Test/Files/bigeve.json")


class TestIDSAlertObject(unittest.TestCase):

    def test_IDS_alert_valid_opts(self):
        try:
            test_alert = IDSAlert(
                dest_ip="192.168.56.107",
                src_ip="192.168.56.1",
                message="Possible Nmap User-Agent Observed",
                timestamp=datetime.datetime.now(),
                log_source=LogSource(
                    "Suricata", "/var/log/suricata/eve.json", 20,
                    AlertFields(
                        "\\dest_ip",
                        "\\src_ip",
                        "\\message",
                        "\\timestamp",
                        "\\category",
                        severity="\\severity"
                    ),
                    20,
                ),
                category="Web Application Attack",
                severity=1
            )
            self.assertTrue(True)
        except Exception as e:
            print(e)
            self.assertTrue(False)

    def test_IDS_alert_str(self):
        timestamp = datetime.datetime.now()
        test_alert = IDSAlert(
            dest_ip="192.168.56.107",
            src_ip="192.168.56.1",
            message="Possible Nmap User-Agent Observed",
            timestamp=timestamp,
            log_source=LogSource(
                "Suricata", "/var/log/suricata/eve.json", 20, fields=
                AlertFields(
                    "\\dest_ip",
                    "\\src_ip",
                    "\\message",
                    "\\timestamp",
                    "\\category",
                    severity= "\\severity"
                ),
                reliability=20
            ),
            category="Web Application Attack",
            severity=1
        )
        try:
            self.assertEqual(test_alert.__str__(),
                             "{},192.168.56.1,192.168.56.107,Possible Nmap User-Agent Observed,Web Application Attack,Suricata".format(timestamp))
        except Exception as e:
            print(e)
            self.assertTrue(False)


if __name__ == "__main__":
    unittest.main()
