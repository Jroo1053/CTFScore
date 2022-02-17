from pytest_httpserver.httpserver import HTTPServer
import os
from time import sleep
import unittest
import subprocess
from unittest import result
LOGGER_FILE_LOCATION = "/home/joe/Development/QualitativeCTF/Source/logger.py"


class TestLoggerFunctionality(unittest.TestCase):

    def test_with_no_issues(self):
        # Spool up a test server to allow http connections to go through

        local_port = 8080
        with HTTPServer(host="127.0.0.1", port=local_port) as test_server:
            test_server.expect_request("/forward", method="POST")\
                .respond_with_json({"Received": "True"})
            logger_no_issues = subprocess.Popen(
                ["python3", LOGGER_FILE_LOCATION, "-c",
                "/home/joe/Development/QualitativeCTF/Test/Files/workingconfig.yml"])
            sleep(10)
            if test_server.log:
                self.assertTrue(True)
            else:
                self.assertTrue(False)

    def test_no_configs(self):
        logger_no_configs = subprocess.Popen(["python3", LOGGER_FILE_LOCATION])
        logger_no_configs.communicate()[0]
        result = logger_no_configs.returncode
        self.assertEqual(1, result)

    def test_broken_config_without_default_path(self):
        if os.path.exists("/etc/ctfscorelog/config.yml"):
            os.remove("/etc/ctfscorelog/config.yml")

        logger_broken_configs = subprocess.Popen(
            ["python3", LOGGER_FILE_LOCATION,
             "-c", "Test/Files/brokenconfig.yml"]
        )
        logger_broken_configs.communicate()[0]
        result = logger_broken_configs.returncode

        self.assertEqual(1, result)

        with open("Test/Files/workingconfig.yml", "r") as working_config:
            with open("/etc/ctfscorelog/config.yml", "w") as default_config:
                for line in working_config:
                    default_config.write(line)

    def test_broken_config_with_default_path(self):
        with open("Test/Files/workingconfig.yml", "r") as working_config:
            with open("/etc/ctfscorelog/config.yml", "w") as default_config:
                for line in working_config:
                    default_config.write(line)

        logger_broken_config_default_path = subprocess.Popen(
            ["python3", LOGGER_FILE_LOCATION,
             "-c", "Test/Files/brokenconfig.yml"]
        )
        logger_broken_config_default_path.communicate()[0]
        result = logger_broken_config_default_path.returncode
        self.assertEqual(1, result)
        if os.path.exists("/etc/ctfscorelog/config.yml"):
            os.remove("/etc/ctfscorelog/config.yml")

    def test_no_access_to_api(self):
        """
        Clone of the no issues test without starting the test api
        """
        logger_no_api = subprocess.Popen(
            ["python3", LOGGER_FILE_LOCATION], "-c",
            "Test/Files/workingconfig.yml")
        logger_no_api.communicate()[0]
        result = logger_no_api.returncode()
        self.assertEqual(0, result)

    def test_intermintent_api_access(self):
        os.chdir(".")
        server = HTTPServer(server_address=("127.0.0.1", 8080),
                            RequestHandlerClass=CGIHTTPRequestHandler)
        server.serve_forever()
        logger_intermintent_api = subprocess.Popen(
            ["python3", LOGGER_FILE_LOCATION], "-c",
            "Test/Files/workingconfig.yml")
        for x in range(5):
            server.shutdown()
            sleep(2)
            server.serve_forever()
            sleep(2)
        result = logger_intermintent_api.returncode()
        self.assertEqual(0, result)


if __name__ == "__main__":
    unittest.main()
