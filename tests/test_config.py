"""The test-mode guard: the fake judge needs a second explicit signal."""
import pytest

from llm_url_scan.config import TEST_MODE_ACK, Config


def test_test_mode_without_the_second_signal_refuses_to_start():
    with pytest.raises(SystemExit, match="judges nothing"):
        Config.from_env({"LLMURL_TEST_MODE": "1"})


def test_test_mode_with_the_second_signal_and_default_mode():
    assert Config.from_env({"LLMURL_TEST_MODE": "1", TEST_MODE_ACK: "1"}).test_mode is True
    assert Config.from_env({}).test_mode is False


def test_shop_routing_is_off_unless_exactly_1_and_could_not_scan_on_unless_0():
    assert Config.from_env({}).shop_routing is False
    assert [Config.from_env({"LLMURL_SHOP_ROUTING": v}).shop_routing for v in ("", "0", "false", "off", "1")] == [False, False, False, False, True]
    assert [Config.from_env({"LLMURL_COULD_NOT_SCAN": v}).could_not_scan for v in ("", "1", "0")] == [True, True, False]
    assert Config.from_env({}).could_not_scan is True


def test_service_built_without_the_argument_has_shop_routing_off():
    import inspect
    from llm_url_scan.service import Service
    assert inspect.signature(Service.__init__).parameters["shop_routing"].default is False
