"""Unit tests for the mock model (no LiteLLM, no network beyond loopback)."""

import json
import threading
import unittest
import urllib.error
import urllib.request

import mock_openai as m

MSG = [{"role": "user", "content": "hello there agent"}]


class Pure(unittest.TestCase):
    def test_usage_counts(self):
        r = m.complete("mock-1", MSG)
        self.assertEqual(r["usage"]["prompt_tokens"], 3)
        self.assertEqual(r["usage"]["completion_tokens"], m.words(r["choices"][0]["message"]["content"]))
        self.assertEqual(r["usage"]["total_tokens"], r["usage"]["prompt_tokens"] + r["usage"]["completion_tokens"])

    def test_deterministic(self):
        self.assertEqual(m.complete("mock-1", MSG), m.complete("mock-1", MSG))

    def test_different_messages_differ(self):
        other = [{"role": "user", "content": "hello there agent!"}]
        self.assertNotEqual(m.complete("mock-1", MSG)["id"], m.complete("mock-1", other)["id"])

    def test_reply_is_labelled(self):
        self.assertTrue(m.complete("mock-1", MSG)["choices"][0]["message"]["content"].startswith("TEST DATA"))

    def test_no_usage_model_omits_usage(self):
        self.assertNotIn("usage", m.complete(m.MODEL_NO_USAGE, MSG))

    def test_parse_rejects(self):
        for body in (b"", b"[]", b"{}", b'{"model":"x"}', b'{"model":"x","messages":[]}',
                     b'{"model":"x","messages":[{"role":"user"}]}', b'{"model":"","messages":[{"role":"u","content":"c"}]}',
                     b'{"model":"x","messages":[{"role":"user","content":5}]}', b"\xff"):
            with self.subTest(body=body), self.assertRaises(m.BadRequest):
                m.parse(body)


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = m.serve(0)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/v1/chat/completions"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def post(self, body: bytes):
        req = urllib.request.Request(self.url, data=body, headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_ok(self):
        code, body = self.post(json.dumps({"model": "mock-1", "messages": MSG}).encode())
        self.assertEqual(code, 200)
        self.assertEqual(body, m.complete("mock-1", MSG))

    def test_bad_request(self):
        self.assertEqual(self.post(b'{"model":"x"}')[0], 400)

    def test_injected_error(self):
        self.assertEqual(self.post(json.dumps({"model": m.MODEL_ERROR, "messages": MSG}).encode())[0], 500)

    def test_binds_loopback_only(self):
        self.assertEqual(self.srv.server_address[0], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
