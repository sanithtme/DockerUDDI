from argparse import Namespace

from demo_cli.main import _synthetic_mac


def test_synthetic_mac_is_deterministic_and_unicast():
    assert _synthetic_mac("02:dd:10", 1) == "02:dd:10:00:00:01"
    assert _synthetic_mac("02:dd:10", 258) == "02:dd:10:00:01:02"


def test_synthetic_mac_rejects_multicast_prefix():
    try:
        _synthetic_mac("03:dd:10", 1)
    except Exception as exc:
        assert "unicast" in str(exc)
    else:
        raise AssertionError("expected multicast prefix rejection")
