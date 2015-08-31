from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import time
import logging
import os


log = logging.getLogger(__name__)


class WildfireProvider(BinaryAnalysisProvider):
    def __init__(self, name):
        super(WildfireProvider, self).__init__(name)

    def check_result_for(self, md5sum):
        # TODO: finish
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        # TODO: finish
        pass


class WildfireConnector(DetonationDaemon):
    @property
    def num_quick_scan_threads(self):
        return 0

    @property
    def num_deep_scan_threads(self):
        return 4

    def get_provider(self):
        wildfire_provider = WildfireProvider(self.name)
        return wildfire_provider

    def get_metadata(self):
        # TODO: finish
        return cbint.utils.feed.generate_feed(self.name, summary="SUMMARY PLACEHOLDER",
                        tech_data="TECH DATA PLACEHOLDER",
                        provider_url="PROVIDER URL",
                        icon_path='/usr/share/cb/integrations/wildfire/wildfire-logo.png',
                        display_name="Wildfire", category="Connectors")

    def validate_config(self):
        super(WildfireConnector, self).validate_config()

        # TODO: finish

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/wildfire"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = WildfireConnector('wildfiretest', configfile=config_path, work_directory=temp_directory,
                                logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()