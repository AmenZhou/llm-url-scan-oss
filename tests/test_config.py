"""The test-mode guard: the fake judge needs a second explicit signal."""
import pytest

from llm_url_scan.config import TEST_MODE_ACK, Config


def test_test_mode_without_the_second_signal_refuses_to_start():
    with pytest.raises(SystemExit, match="judges nothing"):
        Config.from_env({"LLMURL_TEST_MODE": "1"})


def test_test_mode_with_the_second_signal_and_default_mode():
    assert Config.from_env({"LLMURL_TEST_MODE": "1", TEST_MODE_ACK: "1"}).test_mode is True
    assert Config.from_env({}).test_mode is False
