import pytest

from core.kvm_keymap import (
    EXCLUDED_HID,
    HID_TO_MAC_VK,
    HID_TO_WIN_SCAN,
    MAC_VK_TO_HID,
    WIN_SCAN_TO_HID,
    hid_to_mac_vk,
    hid_to_win_scan,
    hid_is_modifier,
    mac_vk_to_hid,
    modifier_hids_for_mask,
    win_scan_to_hid,
)


def test_mac_known_values():
    assert mac_vk_to_hid(0x00) == 0x04  # A
    assert mac_vk_to_hid(0x31) == 0x2C  # Space
    assert mac_vk_to_hid(0x24) == 0x28  # Return
    assert mac_vk_to_hid(0x33) == 0x2A  # Backspace
    assert mac_vk_to_hid(0x35) == 0x29  # Escape
    assert mac_vk_to_hid(0x38) == 0x95  # Left Shift
    assert mac_vk_to_hid(0x7B) == 0x50  # Left arrow


def test_mac_unknown_dropped():
    assert mac_vk_to_hid(0x34) is None  # unused keycode
    assert mac_vk_to_hid(0x3F) is None  # Fn
    assert mac_vk_to_hid(0x72) is None  # Help


def test_mac_to_hid_is_bijection():
    assert len(set(MAC_VK_TO_HID.values())) == len(MAC_VK_TO_HID)
    for vk, hid in MAC_VK_TO_HID.items():
        assert HID_TO_MAC_VK[hid] == vk
    for hid, vk in HID_TO_MAC_VK.items():
        assert MAC_VK_TO_HID[vk] == hid


def test_hid_mac_roundtrip_standard_keys():
    for hid in range(0x04, 0x1E):  # a-z
        assert hid_to_mac_vk(hid) is not None
    for hid in range(0x1E, 0x28):  # 1-0
        assert hid_to_mac_vk(hid) is not None
    for hid in [0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]:
        assert hid_to_mac_vk(hid) is not None


def test_win_known_values():
    assert hid_to_win_scan(0x04) == (0x1E, False)  # A
    assert hid_to_win_scan(0x2C) == (0x39, False)  # Space
    assert hid_to_win_scan(0x28) == (0x1C, False)  # Enter
    assert hid_to_win_scan(0x29) == (0x01, False)  # Escape
    assert hid_to_win_scan(0x95) == (0x2A, False)  # Left Shift
    assert hid_to_win_scan(0x99) == (0x36, False)  # Right Shift


def test_win_extended_keys():
    assert hid_to_win_scan(0x98) == (0x1D, True)  # Right Control
    assert hid_to_win_scan(0x9A) == (0x38, True)  # Right Alt / AltGr
    assert hid_to_win_scan(0x97) == (0x5B, True)  # Left GUI
    assert hid_to_win_scan(0x52) == (0x48, True)  # Up arrow
    assert hid_to_win_scan(0x4C) == (0x53, True)  # Delete
    assert hid_to_win_scan(0x4A) == (0x47, True)  # Home
    assert hid_to_win_scan(0x58) == (0x1C, True)  # Keypad Enter
    assert hid_to_win_scan(0x54) == (0x35, True)  # Keypad /


def test_win_scan_inverse():
    assert len(WIN_SCAN_TO_HID) == len(HID_TO_WIN_SCAN)
    for hid, (scan, ext) in HID_TO_WIN_SCAN.items():
        assert win_scan_to_hid(scan, ext) == hid
    for (scan, ext), hid in WIN_SCAN_TO_HID.items():
        assert hid_to_win_scan(hid) == (scan, ext)


def test_excluded_hid_never_maps():
    for hid in EXCLUDED_HID:
        assert hid_to_win_scan(hid) is None
        assert hid_to_mac_vk(hid) is None


def test_modifiers():
    assert hid_is_modifier(0x94)
    assert hid_is_modifier(0x9A)
    assert not hid_is_modifier(0x04)
    assert modifier_hids_for_mask(1) == [0x95]  # shift -> left shift
    assert modifier_hids_for_mask(16) == [0x9A]  # altgr stays right alt
    assert set(modifier_hids_for_mask(1 | 2)) == {0x95, 0x94}


pytestmark = pytest.mark.unit
