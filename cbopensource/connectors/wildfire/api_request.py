from threading import Lock
from datetime import datetime, timedelta
import time
import logging
from requests.adapters import HTTPAdapter
from requests import Session
import sys

log = logging.getLogger(__name__)


class APIQuotaExceededError(Exception):
    pass


class APISession(Session):
    def __init__(self, request_quota=None, throttle_per_minute=None, api_keys=None):
        super(APISession, self).__init__()
        self.request_quota = request_quota
        self.throttle_per_minute = throttle_per_minute
        if not api_keys or type(api_keys) != list:
            raise Exception("Need list of API keys")

        self.api_keys = api_keys
        self.current_api_key_index = 0

        self.request_lock = Lock()

        self.total_request_count = 0
        self.total_reply_count = 0

        # throttling
        self.current_minute = datetime.now()
        self.requests_current_minute = 0

        # quota
        self.current_quota_usage = 0

        self.wait_until = None

    def apply_api_key(self, request):
        if len(self.api_keys) == 0:
            log.fatal("No valid API keys remaining, exiting")
            sys.exit(2)

        if request.method == "GET":
            return request
        elif type(request.data) == dict:
            request.data['apikey'] = self.api_keys[self.current_api_key_index]

        return request

    def prepare_request(self, request):
        request = self.apply_api_key(request)
        return super(APISession, self).prepare_request(request)

    def send(self, request, **kwargs):
        if self.request_quota:
            self.current_quota_usage += 1
            if self.current_quota_usage > self.request_quota:
                self.set_wait_time()

        if self.wait_until:
            sleep_time = (self.wait_until - datetime.now()).total_seconds()
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.wait_until = None

        # next, apply throttling
        if self.throttle_per_minute:
            now = datetime.now()
            if now - self.current_minute > timedelta(minutes=1):
                self.current_minute = now
                self.requests_current_minute = 0
            else:
                self.requests_current_minute += 1

            if self.requests_current_minute > self.throttle_per_minute:
                log.info("Too many API requests in the past 60 seconds (limit is {0}). Waiting one minute..."
                         .format(self.throttle_per_minute))
                time.sleep(60)
                self.requests_current_minute = 0
                self.current_minute = datetime.now()

        return super(APISession, self).send(request, **kwargs)

    def increment_api_key(self):
        # API key quota exceeded
        log.info("Reached quota for API key {0}".format(self.api_keys[self.current_api_key_index]))
        self.current_api_key_index += 1
        if self.current_api_key_index == len(self.api_keys):
            # we've tried all our API keys, so we have to wait...
            self.set_wait_time()
            self.current_api_key_index = 0

    def set_wait_time(self):
        if self.wait_until:
            return

        # default quota strategy: wait an hour before trying again
        next_time = datetime.now()
        self.wait_until = next_time.replace(hour=(next_time.hour+1))

        log.info("Reached API quota limit for all API keys. Waiting until {0} to try again.".format(self.wait_until))
        self.current_quota_usage = 0

    def request(self, *args, **kwargs):
        with self.request_lock:
            successful = False

            while not successful:
                self.total_request_count += 1
                response = super(APISession, self).request(*args, **kwargs)
                self.total_reply_count += 1

                if response.status_code == 419:
                    self.increment_api_key()
                    continue
                else:
                    return response


class WildFireAPIRequestMiddleware(HTTPAdapter):
    def __init__(self, request_quota=None, throttle_per_minute=None, api_keys=None, *args, **kwargs):
        super(WildFireAPIRequestMiddleware, self).__init__(*args, **kwargs)

        self.request_quota = request_quota
        self.throttle_per_minute = throttle_per_minute
        if not api_keys or type(api_keys) != list:
            raise Exception("Need list of API keys")

        self.api_keys = api_keys
        self.current_api_key_index = 0

        self.request_lock = Lock()

        self.total_request_count = 0
        self.total_reply_count = 0

        # throttling
        self.current_minute = datetime.now()
        self.requests_current_minute = 0

        # quota
        self.current_quota_usage = 0

        self.wait_until = None

    def set_wait_time(self):
        if self.wait_until:
            return

        # default quota strategy: wait an hour before trying again
        next_time = datetime.now()
        self.wait_until = next_time.replace(hour=(next_time.hour+1))

        log.info("Reached API quota limit for all API keys. Waiting until {0} to try again.".format(self.wait_until))
        self.current_quota_usage = 0

    def apply_api_key(self, request, original_body):
        if len(self.api_keys) == 0:
            log.fatal("No valid API keys remaining, exiting")
            sys.exit(2)

        if request.method == "GET":
            return request

        if not original_body or not len(original_body):
            request.headers['Content-Type'] = "application/x-www-form-urlencoded"
            request.body = "apikey=%s" % self.api_keys[self.current_api_key_index]
        else:
            request.body = "%s&apikey=%s" % (original_body, self.api_keys[self.current_api_key_index])

        request.headers['Content-Length'] = len(request.body)
        return request

    def after_send(self, response):
        if response.status_code == 419:
            # API key quota exceeded
            log.info("Reached quota for API key {0}".format(self.api_keys[self.current_api_key_index]))
            self.current_api_key_index += 1
            if self.current_api_key_index == len(self.api_keys):
                # we've tried all our API keys, so we have to wait...
                self.set_wait_time()
                self.current_api_key_index = 0
            return False

        elif response.status_code == 401:
            log.error("Received unauthorized (401) for API key {0}".format(self.api_keys[self.current_api_key_index]))
            # API key invalid, remove it from the list
            del self.api_keys[self.current_api_key_index]
            if len(self.api_keys) == 0:
                log.fatal("No valid API keys remaining, exiting")
                sys.exit(2)
            return False

        return True

    def send(self, request, *args, **kwargs):
        with self.request_lock:
            successful = False

            original_body = request.body

            while not successful:
                self.before_send(request, *args, **kwargs)
                # apply API keys
                request = self.apply_api_key(request, original_body)

                self.total_request_count += 1
                response = self.throttle_send(request, *args, **kwargs)

                if self.after_send(response):
                    self.total_reply_count += 1
                    return response

    def throttle_send(self, request, *args, **kwargs):
        # next, apply throttling
        if self.throttle_per_minute:
            now = datetime.now()
            if now - self.current_minute > timedelta(minutes=1):
                self.current_minute = now
                self.requests_current_minute = 0
            else:
                self.requests_current_minute += 1

            if self.requests_current_minute > self.throttle_per_minute:
                log.info("Too many API requests in the past 60 seconds (limit is {0}). Waiting one minute..."
                         .format(self.throttle_per_minute))
                time.sleep(60)
                self.requests_current_minute = 0
                self.current_minute = datetime.now()

        return super(WildFireAPIRequestMiddleware, self).send(request, *args, **kwargs)

    def before_send(self, request, *args, **kwargs):
        # first, check to see if we're above quota
        if self.request_quota:
            self.current_quota_usage += 1
            if self.current_quota_usage > self.request_quota:
                self.set_wait_time()

        if self.wait_until:
            sleep_time = (self.wait_until - datetime.now()).total_seconds()
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.wait_until = None

