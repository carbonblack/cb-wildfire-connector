from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult, AnalysisInProgress)
import cbint.utils.feed
from cbapi.connection import CbAPISessionAdapter
import time
import logging
import os
import sys

from api_request import APISession

from lxml import etree


log = logging.getLogger(__name__)


class WildfireProvider(BinaryAnalysisProvider):
    def __init__(self, name, wildfire_url, wildfire_ssl_verify, api_keys, work_directory):
        super(WildfireProvider, self).__init__(name)
        self.api_keys = api_keys
        self.wildfire_url = wildfire_url
        self.wildfire_ssl_verify = wildfire_ssl_verify
        self.current_api_key_index = 0
        self.session = APISession(api_keys=self.api_keys, throttle_per_minute=120)
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        self.session.mount("https://", tls_adapter)
        self.work_directory = work_directory

    def get_api_key(self):
        for i in range(len(self.api_keys)):
            yield self.api_keys[self.current_api_key_index]

            self.current_api_key_index += 1
            self.current_api_key_index %= len(self.api_keys)

        # if we've gotten here, we have no more keys to give.

    def _call_wildfire_api(self, method, path, payload=None, files=None):
        url = self.wildfire_url + path

        if method == 'GET':
            try:
                r = self.session.get(url, verify=self.wildfire_ssl_verify)
            except Exception as e:
                log.exception("Exception when sending WildFire API GET request: %s" % e)
                raise

            return r.status_code, r.content
        elif method == 'POST':
            try:
                r = self.session.post(url, data=payload, files=files, verify=self.wildfire_ssl_verify)
            except Exception as e:
                log.exception("Exception when sending WildFire API query: %s" % e)
                # bubble this up as necessary
                raise
            return r.status_code, r.content

    def query_wildfire(self, md5sum):
        """
        query the wildfire api to get a report on an md5
        """
        log.info("Querying wildfire for md5sum %s" % md5sum)

        status_code, content = self._call_wildfire_api("POST", "/publicapi/get/verdict",
                                                       {'hash': md5sum.lower()})

        if status_code == 404:
            return None                       # can't find the binary
        elif status_code != 200:
            log.info("Received unknown HTTP status code %d from WildFire" % status_code)
            log.info("-> response content: %s" % content)
            raise AnalysisTemporaryError("Received unknown HTTP status code %d from WildFire" % status_code,
                                         retry_in=120)

        response = etree.fromstring(content)

        # Return 0 Benign verdict
        # 1 Malware verdict
        # 2 Grayware verdict
        # -100 Verdict is pending
        # -101 Indicates a file error
        # -102 The file could not be found
        # -103 The hash submitted is invalid
        if md5sum.lower() == response.findtext("./get-verdict-info/md5").lower():
            verdict = response.findtext("./get-verdict-info/verdict").strip()
            if verdict == "-100":
                return None                # waiting for WildFire verdict
            elif verdict == "-102":
                return None                # file not in WildFire yet
            elif verdict.startswith("-"):
                raise AnalysisPermanentError("WildFire could not process file: error %s" % verdict)
            elif verdict == "1":
                return self.generate_malware_result(md5sum, 100)
            elif verdict == "2":
                return self.generate_malware_result(md5sum, 50)
            else:
                return AnalysisResult(score=0)

    def generate_malware_result(self, md5, score):
        status_code, content = self._call_wildfire_api("POST", "/publicapi/get/report",
                                                       {'hash': md5.lower(), "format": "pdf"})

        if status_code == 200:
            open(os.path.join(self.work_directory, md5.upper()) + ".pdf", 'wb').write(content)
            return AnalysisResult(score=score, link="/reports/%s.pdf" % md5.upper())
        else:
            return AnalysisResult(score=score)

    def submit_wildfire(self, md5sum, file_stream):
        """
        submit a file to the wildfire api
        returns a wildfire submission status code
        """

        files = {'file': ('CarbonBlack_%s' % md5sum, file_stream)}
        try:
            status_code, content = self._call_wildfire_api("POST", "/publicapi/submit/file", files=files)
        except Exception as e:
            log.exception("Exception while submitting MD5 %s to WildFire: %s" % (md5sum, e))
            raise AnalysisTemporaryError("Exception while submitting to WildFire: %s" % e)
        else:
            if status_code == 200:
                return True
            else:
                raise AnalysisTemporaryError("Received HTTP error code %d while submitting to WildFire" % status_code)

    def check_result_for(self, md5sum):
        return self.query_wildfire(md5sum)

    def analyze_binary(self, md5sum, binary_file_stream):
        self.submit_wildfire(md5sum, binary_file_stream)

        retries = 20
        while retries:
            time.sleep(30)
            result = self.check_result_for(md5sum)
            if result:
                return result
            retries -= 1

        raise AnalysisTemporaryError(message="Maximum retries (20) exceeded submitting to WildFire", retry_in=120)


class WildfireConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('(os_type:windows) orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        log.info("Filter spec is %s" % ' '.join(filters))

        return ' '.join(filters)

    @property
    def integration_name(self):
        return 'Cb Wildfire Connector 2.5.7'

    @property
    def num_quick_scan_threads(self):
        return 1

    @property
    def num_deep_scan_threads(self):
        return 4

    def get_provider(self):
        wildfire_provider = WildfireProvider(self.name, self.wildfire_url, self.wildfire_ssl_verify, self.api_keys,
                                             self.work_directory)
        return wildfire_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="PaloAlto Wildfire cloud binary feed",
                        tech_data=("There are no requirements to share any data with Carbon Black to use this feed. "
                                   "However, binaries may be shared with Palo Alto."),
                        provider_url="http://wildfire.paloaltonetworks.com/",
                        icon_path='/usr/share/cb/integrations/wildfire/wildfire-logo.png',
                        display_name="Wildfire", category="Connectors")

    def validate_config(self):
        super(WildfireConnector, self).validate_config()

        keys = self.get_config_string("wildfire_api_keys", None)
        if not keys:
            raise ConfigurationError("WildFire API keys must be specified in the wildfire_api_keys option")
        self.api_keys = keys.split(';')

        wildfire_url = self.get_config_string("wildfire_url", "https://wildfire.paloaltonetworks.com")
        self.wildfire_url = wildfire_url.rstrip("/")

        self.wildfire_ssl_verify = self.get_config_boolean("wildfire_verify_ssl", True)

        log.info("connecting to WildFire server at %s with API keys %s" % (self.wildfire_url, self.api_keys))

        return True


if __name__ == '__main__':
#    import yappi
    import logging
    logging.basicConfig(level=logging.DEBUG)

#    yappi.start()

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/wildfire"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = WildfireConnector('wildfiretest', configfile=config_path, work_directory=temp_directory,
                                    logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()

#    yappi.get_func_stats().print_all()
#    yappi.get_thread_stats().print_all()

