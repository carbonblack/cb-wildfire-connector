from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import time
import logging
import os
import requests


log = logging.getLogger(__name__)


class WildfireProvider(BinaryAnalysisProvider):
    def __init__(self, name, api_keys):
        super(WildfireProvider, self).__init__(name)
        self.api_keys = api_keys
        self.current_api_key_index = 0

    def get_api_key(self):
        for i in range(len(self.api_keys)):
            yield self.api_keys[self.current_api_key_index]

            self.current_api_key_index += 1
            self.current_api_key_index %= len(self.api_keys)

        # if we've gotten here, we have no more keys to give.

    def query_wildfire(self, md5):
        """
        query the wildfire api to get a report on an md5
        returns a dictionary
            status_code: the wildfire api status code
            malware: 1 if determined to be malware, otherwise 0
        """
        success = False
        try:
            for apikey in self.get_api_key():
                url = 'https://wildfire.paloaltonetworks.com/get-report-xml'
                payload = {'md5': md5, 'apikey': apikey}
                r = requests.post(url, data=payload)
                if r.status_code == 200:
                    success = True
                    break
                elif r.status_code == 404:
                    return None                # can't find the binary
                elif r.status_code == 419:
                    log.info("API query quota reached for key %s, trying next key" % apikey)
                elif r.status_code == 401:
                    log.info("API key %s unauthorized, trying next key" % apikey)
                else:
                    log.info("Received unknown HTTP status code %d from WildFire" % r.status_code)
                    raise AnalysisTemporaryError("Received unknown HTTP status code %d from WildFire" % r.status_code,
                                                 retry_in=120)

            if not success:
                raise AnalysisTemporaryError("No working WildFire API keys", retry_in=120)
        except AnalysisTemporaryError as e:
            raise
        except Exception as e:
            raise AnalysisTemporaryError("an exception occurred while querying wildfire: %s" % e)
        else:
            if success:
                if r.text.find('<malware>yes</malware>') >= 0:
                    return AnalysisResult(score=100)
                else:
                    return AnalysisResult(score=0)

    def submit_wildfire(self, md5sum, file_stream):
        """
        submit a file to the wildfire api
        returns a wildfire submission status code
        """
        file_bytes = file_stream.read()
        success = False
        try:
            for apikey in self.get_api_key():
                url = 'https://wildfire.paloaltonetworks.com/submit-file'
                payload = {'apikey': apikey}
                files = {'file': ('sample', file_bytes)}
                r = requests.post(url, data=payload, files=files)
                if r.status_code == 200:
                    success = True
                elif r.status_code == 419:
                    log.info("API query quota reached for key %s, trying next key" % apikey)
                elif r.status_code == 401:
                    log.info("API key %s unauthorized, trying next key" % apikey)
                else:
                    log.info("Received unknown HTTP status code %d from WildFire" % r.status_code)
                    raise AnalysisTemporaryError("Received unknown HTTP status code %d from WildFire" % r.status_code,
                                                 retry_in=120)

            if not success:
                raise AnalysisTemporaryError("No working WildFire API keys", retry_in=120)
        except AnalysisTemporaryError as e:
            raise
        except Exception as e:
            raise AnalysisTemporaryError("an exception occurred while submitting to wildfire: %s" % e)
        else:
            return True

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
    def num_quick_scan_threads(self):
        return 0

    @property
    def num_deep_scan_threads(self):
        return 4

    def get_provider(self):
        wildfire_provider = WildfireProvider(self.name, self.api_keys)
        return wildfire_provider

    def get_metadata(self):
        # TODO: finish
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

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/wildfire"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = WildfireConnector('wildfiretest', configfile=config_path, work_directory=temp_directory,
                                logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()