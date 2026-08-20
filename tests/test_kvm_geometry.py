import pytest

from core.kvm_geometry import (
    JUMP_ZONE,
    GeometryError,
    Monitor,
    ScreenLayout,
    clamp_to_edge,
    in_jump_zone,
    map_to_peer,
    entry_point,
    opposite_side,
    pt_to_px,
    px_to_pt,
    seam_fraction,
    verify_topology,
)


def layout(w=1440, h=900, x=0, y=0, scale=1.0):
    return ScreenLayout([Monitor(x, y, w, h, scale)], primary=0)


def test_opposite():
    assert opposite_side("left") == "right"
    assert opposite_side("top") == "bottom"


def test_bounds():
    s = layout(1440, 900)
    assert (s.left(), s.top(), s.right(), s.bottom()) == (0, 0, 1440, 900)


def test_layout_requires_monitor():
    with pytest.raises(GeometryError):
        ScreenLayout([])


def test_jump_zone_sides():
    s = layout()
    assert in_jump_zone(s, 0, 400) == "left"
    assert in_jump_zone(s, JUMP_ZONE, 400) == "left"
    assert in_jump_zone(s, 1439, 400) == "right"
    assert in_jump_zone(s, 1439 - JUMP_ZONE, 400) == "right"
    assert in_jump_zone(s, 700, 0) == "top"
    assert in_jump_zone(s, 700, 899) == "bottom"
    assert in_jump_zone(s, 700, 400) is None


def test_jump_zone_corner_prefers_horizontal():
    s = layout()
    assert in_jump_zone(s, 0, 0) == "left"  # horizontal first
    assert in_jump_zone(s, 1439, 0) == "right"
    assert in_jump_zone(s, 100, 0) == "top"  # only vertical in zone


def test_clamp():
    s = layout()
    assert clamp_to_edge(s, 0, 400) == (0, 400)
    assert clamp_to_edge(s, 1439, 400) == (1439, 400)
    assert clamp_to_edge(s, 700, 899) == (700, 899)
    assert clamp_to_edge(s, 700, 400) == (700, 400)


def test_seam_fraction_left_right():
    s = layout(h=900)
    assert seam_fraction(s, "right", 1439, 450) == pytest.approx(450 / 899)
    assert seam_fraction(s, "right", 1439, 0) == pytest.approx(0.0)
    assert seam_fraction(s, "right", 1439, 899) == pytest.approx(1.0)
    assert seam_fraction(s, "left", 0, 225) == pytest.approx(225 / 899)
    # out-of-range clamps
    assert seam_fraction(s, "right", 1439, 2000) == pytest.approx(1.0)
    assert seam_fraction(s, "right", 1439, -50) == pytest.approx(0.0)


def test_seam_fraction_top_bottom():
    s = layout(w=1440)
    assert seam_fraction(s, "bottom", 720, 899) == pytest.approx(720 / 1439)
    assert seam_fraction(s, "top", 0, 0) == pytest.approx(0.0)
    assert seam_fraction(s, "bottom", 1439, 899) == pytest.approx(1.0)


def test_map_to_peer_unequal_heights():
    # peer sits to my right; a seam on my right lands on the peer's LEFT edge
    peer = layout(w=1920, h=1080)
    x, y = map_to_peer(peer, "right", 0.5)
    assert x == peer.left()
    assert y == 539  # middle of the peer's left edge
    x, y = map_to_peer(peer, "left", 0.25)
    assert x == peer.right() - 1
    assert y == 269


def test_map_to_peer_top_bottom():
    peer = layout(w=2560, h=1440)
    # seam on my bottom lands on the peer's TOP edge
    x, y = map_to_peer(peer, "bottom", 0.5)
    assert x == 1279
    assert y == peer.top()
    x, y = map_to_peer(peer, "top", 0.25)
    assert x == 639
    assert y == peer.bottom() - 1


def test_map_to_peer_clamps_fraction():
    peer = layout(w=1920, h=1080)
    assert map_to_peer(peer, "right", 2.0) == (peer.left(), peer.bottom() - 1)
    assert map_to_peer(peer, "right", -1.0) == (peer.left(), peer.top())


def test_entry_point_lands_past_the_return_zone():
    peer = ScreenLayout([Monitor(0, 0, 1920, 1080)])
    assert entry_point(peer, "right", 0.5) == (48, 539)


def test_topology():
    assert verify_topology("right", "left")
    assert verify_topology("left", "right")
    assert verify_topology("top", "bottom")
    assert not verify_topology("right", "right")
    assert not verify_topology("right", "top")


def test_offscreen_monitor_union():
    s = ScreenLayout([Monitor(0, 0, 1440, 900), Monitor(1440, 0, 1920, 1080)])
    assert s.right() == 1440 + 1920
    assert in_jump_zone(s, s.right() - 1, 500) == "right"


def test_scale_conversion():
    assert pt_to_px(100, 2.0) == 200
    assert px_to_pt(200, 2.0) == 100
    assert pt_to_px(0, 1.0) == 0


pytestmark = pytest.mark.unit
