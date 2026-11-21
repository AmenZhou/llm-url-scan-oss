"""Test mode for the compose stack tests (LLMURL_TEST_MODE=1, set only by docker-compose.test.yml, never by default): a fake judge and a fake Web Risk
client replace the real ones, so no key file is read and no Anthropic or Google call can happen. The capture path is the real one."""
import json


class FakeJudge:
    """Mimics client.messages.create(**kw): always a benign answer with no quote. Token counts follow the message length so a longer page costs more."""

    def __init__(self):
        self.messages = self

    def create(self, **kw):
        n = len(json.dumps(kw.get("messages", [])))
        text = json.dumps({"verdict": "benign", "rules": [], "brand": None, "quotes": [], "injection_text": False})
        return {"id": "msg_testmode", "stop_reason": "end_turn", "usage": {"input_tokens": n // 4 + 1, "output_tokens": 40}, "content": [{"type": "text", "text": text}]}


class FakeWebRisk:
    def check(self, url):
        return "negative"
