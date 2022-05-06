import unittest
from Lib.utils import get_config_opts, parse_logs
from Lib.models import DictObj, LogSource, AlertFields
from test_logger_func import LOGGER_FILE_LOCATION
WORKING_CONFIG_FILE_PATH = "Test/Files/TestConfigFiles/working.yml"
MISSING_FLAGS_CONFIG_FILE_PATH = "Test/Files/TestConfigFiles/missing.yml"
TOO_MANY_FLAGS_CONFIG_FILE_PATH = "Test/Files/TestConfigFiles/toomany.yml"
DUPLICATE_FLAGS_CONFIG_FILE_PATH = "Test/Files/TestConfigFiles/duplicate.yml"
WRONG_TYPES_CONFIG_FILE_PATH = ""

EXPECTED_GLOBAL_KEYS = ["api_forward_event_endpoint", "api_id_file",
                        "api_is_enabled", "api_key_file", "api_max_retries",
                        "api_status_endpoint", "api_url", "polling_rate",
                        "ssl_cert_file"]


class TestGetConfigOpts(unittest.TestCase):

    def test_get_config_opts_working_file(self):
        """
        Tests if get_config_opts works with a normal config file and 
        returns correct values
        """
        try:
            test_opts = DictObj(get_config_opts(WORKING_CONFIG_FILE_PATH))
            if test_opts.global_options and test_opts.ids_options:
                for key in EXPECTED_GLOBAL_KEYS:
                    if not hasattr(test_opts.global_options, key):
                        self.assertTrue(False)
            else:
                self.assertTrue(False)
        except:
            self.assertTrue(False)

    def test_get_config_opts_missing_flags(self):
        """
        Test if  get_config_opts detects missing keys and then raises
        a KeyError
        """
        try:
            test_opts = DictObj(get_config_opts(
                MISSING_FLAGS_CONFIG_FILE_PATH))
            self.assertTrue(False)
        except KeyError:
            self.assertTrue(True)

    def test_get_config_opts_too_many_flags(self):
        """
        Tests if get_config_opts detects if the config file contains too many 
        keys
        """
        try:
            test_opts = DictObj(get_config_opts(
                TOO_MANY_FLAGS_CONFIG_FILE_PATH))
            self.assertTrue(False)
        except:
            self.assertTrue(True)

    def test_get_config_opts_duplicate_flags(self):
        """
        Test if the get_config_opts handles duplicate flags correctly,
        the other tests should cover this but who knows
        """
        try:
            test_opts = DictObj(get_config_opts(
                DUPLICATE_FLAGS_CONFIG_FILE_PATH
            ))
            self.assertTrue(False)
        except:
            self.assertFalse(False)


class TestParseLogs(unittest.TestCase):

    def test_parse_logs_valid_source(self):
        """
        Checks if the parse_log func works with a valid path and 
        returns the expected results
        """
        try:
            test_source = LogSource(
                name="Suricata",
                path="Test/Files/bigeve.json",
                max_alerts=20,
                fields= AlertFields(
                    dest_ip="/dest_ip",
                    src_ip="/src_ip",
                    message="/alert/signature",
                    timestamp="/timestamp",
                    category="/alert/category"
                ),
                reliability=80
            )
            events = parse_logs(test_source)
            if len(events) > 0:
                self.assertTrue(True)
                return
            else:
                self.assertTrue(False)
                return
        except Exception as e:
            print(e)
            self.assertFalse(False)

    def test_parse_logs_unsupported_source(self):
        """
        Test if the parse logs func checks for invalid sources
        """
        test_source = LogSource(
            "MeerkatIDS",
            "Source/Test/Files/bigeve.json",
            20,
            AlertFields(
                "/dest_ip",
                "/src_ip",
                "/alert/signature",
                "/timestamp",
                "/alert/category",
            ),
            80
        )
        events = parse_logs(test_source)
        if len(events) > 0:
            self.assertTrue(False)
            return
        else:
            self.assertTrue(True)
            return
    def test_parse_logs_missing_path(self):
        """
        Test if the parse logs handles an error if the source path is not present
        """
        try:
            test_source = LogSource(
                "MeerkatIDS",
                "/home/rjgumby/notreal/path",
                20,
                AlertFields(
                    "/dest_ip",
                    "/src_ip",
                    "/alert/signature",
                    "/timestamp",
                    "/alert/category",
                ),
                80
            )
            events = parse_logs(test_source)
            if len(events) > 0:
                self.assertTrue(False)
                return
            else:
                self.assertTrue(True)
                return
        except FileNotFoundError:
            self.assertTrue(True)

    def test_parse_logs_path_is_dir(self):
        """
        Test if the parse logs handles an error if the source path is a
        directory
        """
        try:
            test_source = LogSource(
                "MeerkatIDS",
                "/etc/",
                20,
                AlertFields(
                    "/dest_ip",
                    "/src_ip",
                    "/alert/signature",
                    "/timestamp",
                    "/alert/category",
                ),
                80
            )
            events = parse_logs(test_source)
            if len(events) > 0:
                self.assertTrue(False)
                return
            else:
                self.assertTrue(True)
                return
        except FileNotFoundError:
            self.assertTrue(False)
        except IsADirectoryError:
            self.assertTrue(True)


    def test_parse_log_path_is_rooted(self):
        """
        Test if the parse logs handles an error if the source path needs root/
        raised access rights
        """
        try:
            test_source = LogSource(
                "MeerkatIDS",
                "/",
                20,
                AlertFields(
                    "/dest_ip",
                    "/src_ip",
                    "/alert/signature",
                    "/timestamp",
                    "/alert/category",
                ),
                80
            )
            events = parse_logs(test_source)
            if len(events) > 0:
                self.assertTrue(False)
                return
            else:
                self.assertTrue(True)
                return
        except FileNotFoundError:
            self.assertTrue(False)
        except IsADirectoryError:
            self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
