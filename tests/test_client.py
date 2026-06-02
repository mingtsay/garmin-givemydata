"""Regression tests for garmin_client.client."""

import threading
import time
import unittest

from garmin_client.client import (
    GarminClient,
    OAuth2Token,
    _ProcessLifecycle,
    oauth1_authorization_header,
)


class TestOAuth1Signature(unittest.TestCase):
    """The OAuth1 HMAC-SHA1 signer is hand-rolled (no oauthlib dependency).

    These golden signatures were cross-checked against ``oauthlib.oauth1``
    for the exact Garmin OAuth calls, so they pin the implementation to a
    spec-correct reference. A regression here means tokens won't mint.
    """

    CK = "fc3e99d2-118c-44b8-8ae3-03370dde24c0"
    CS = "E08WAR897WEy2knn7aFBrvegVAf0AFdWBBF"
    NONCE = "abc123nonce456def"
    TS = 1700000000

    def _sig(self, header):
        # Pull oauth_signature="..." out of the OAuth header (it's percent-encoded).
        import re
        from urllib.parse import unquote

        return unquote(re.search(r'oauth_signature="([^"]+)"', header).group(1))

    def test_preauthorized_get_signature(self):
        url = (
            "https://connectapi.garmin.com/oauth-service/oauth/preauthorized"
            "?ticket=ST-123-abc&login-url=https://mobile.integration.garmin.com/gcm/android"
            "&accepts-mfa-tokens=true"
        )
        header = oauth1_authorization_header("GET", url, self.CK, self.CS, nonce=self.NONCE, timestamp=self.TS)
        self.assertEqual(self._sig(header), "xINt7KTyv9pvMSNDmy2n26Li4TU=")

    def test_exchange_post_with_audience_signature(self):
        url = "https://connectapi.garmin.com/oauth-service/oauth/exchange/user/2.0"
        header = oauth1_authorization_header(
            "POST",
            url,
            self.CK,
            self.CS,
            token="RT-token",
            token_secret="rt-secret",
            body_params={"audience": "GARMIN_CONNECT_MOBILE_ANDROID_DI"},
            nonce=self.NONCE,
            timestamp=self.TS,
        )
        self.assertEqual(self._sig(header), "Fkakmsz7zrNHCgrL4HTzS1vKaAI=")

    def test_exchange_post_empty_body_signature(self):
        url = "https://connectapi.garmin.com/oauth-service/oauth/exchange/user/2.0"
        header = oauth1_authorization_header(
            "POST",
            url,
            self.CK,
            self.CS,
            token="RT-token",
            token_secret="rt-secret",
            body_params={},
            nonce=self.NONCE,
            timestamp=self.TS,
        )
        self.assertEqual(self._sig(header), "n5n9YQN2ZHqlJxWK9Mshu0sIPf8=")

    def test_nonce_is_random_by_default(self):
        url = "https://connectapi.garmin.com/oauth-service/oauth/exchange/user/2.0"
        a = oauth1_authorization_header("POST", url, self.CK, self.CS)
        b = oauth1_authorization_header("POST", url, self.CK, self.CS)
        self.assertNotEqual(a, b)


class TestApiUrlTranslation(unittest.TestCase):
    """``/gc-api/<service>`` web paths must map onto connectapi.garmin.com so
    the (unchanged) endpoints.py keeps working over the OAuth/API host."""

    def test_strips_gc_api_prefix(self):
        self.assertEqual(
            GarminClient._api_url("/gc-api/wellness-service/wellness/dailyStress/2024-01-01"),
            "https://connectapi.garmin.com/wellness-service/wellness/dailyStress/2024-01-01",
        )

    def test_preserves_query_string(self):
        self.assertEqual(
            GarminClient._api_url("/gc-api/activitylist-service/activities/search/activities?limit=100&start=0"),
            "https://connectapi.garmin.com/activitylist-service/activities/search/activities?limit=100&start=0",
        )

    def test_passthrough_absolute_url(self):
        url = "https://connectapi.garmin.com/foo/bar"
        self.assertEqual(GarminClient._api_url(url), url)

    def test_path_without_prefix(self):
        self.assertEqual(
            GarminClient._api_url("download-service/files/activity/123"),
            "https://connectapi.garmin.com/download-service/files/activity/123",
        )


class TestOAuth2TokenExpiry(unittest.TestCase):
    def test_fresh_token_not_expired(self):
        tok = OAuth2Token(access_token="x", expires_at=int(time.time()) + 3600)
        self.assertFalse(tok.expired)

    def test_token_within_buffer_is_expired(self):
        tok = OAuth2Token(access_token="x", expires_at=int(time.time()) + 30)
        self.assertTrue(tok.expired)

    def test_authorization_header_format(self):
        tok = OAuth2Token(access_token="abc", token_type="bearer")
        self.assertEqual(tok.authorization(), "Bearer abc")


class TestProcessLifecycleThreadSafety(unittest.TestCase):
    """Issue #35 bug 2: _ProcessLifecycle.install() used to call
    signal.signal() unconditionally. The MCP server runs sync in a
    ThreadPoolExecutor worker, so install() runs from a non-main thread
    and signal.signal() raises ValueError("signal only works in main
    thread of the main interpreter").
    """

    def test_install_from_worker_thread_does_not_raise(self):
        errors: list[BaseException] = []

        def worker():
            try:
                lifecycle = _ProcessLifecycle(cleanup_fn=lambda: None)
                lifecycle.install()
            except BaseException as exc:
                errors.append(exc)

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        self.assertEqual(errors, [], f"install() raised in worker thread: {errors}")


if __name__ == "__main__":
    unittest.main()
