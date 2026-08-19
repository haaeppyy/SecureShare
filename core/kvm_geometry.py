"""Monitor geometry and seam math for keyboard/mouse sharing.

Coordinates are logical units (macOS points / Windows scaled pixels).
Each platform converts to physical pixels at capture/inject time using
the monitor scale factor.

The peer placement is described per-device with a ``side``: "the peer
sits at my <left|right|top|bottom> edge". The seam between the two
machines is that edge on my side and its opposite edge on the peer's
side, so mismatched screen sizes align by proportional position along
the seam (fraction 0..1).

v2: seams are computed against the union bounds of all local monitors
(the true outer edges, so moving between my own monitors never looks
like a seam) with a monitor-membership guard: a point inside the union
but in empty space (uneven monitor heights create such strips) is never
a seam. Seam fractions map against the monitor the cursor is actually
in, so stacked/side-by-side monitors of different sizes align
proportionally per segment.
"""

SIDES = ("left", "right", "top", "bottom")
JUMP_ZONE = 3  # px from an edge that counts as reaching for the neighbor
# Wider zone used ONLY to decide when an edge latch (_blocked_edge) may
# clear after a handoff returns control: the cursor is restored just
# inside the seam (return_point), so a 3 px clear zone would drop the
# latch on the first residual wiggle.  Must stay wider than the return
# point inset (JUMP_ZONE + 1) and is never used for seam detection.
LATCH_ZONE = 8
# A handoff must begin visibly inside the receiving display.  Starting only
# one jump-zone past the edge makes residual motion from the crossing clamp
# the cursor back to that edge before the user can steer it.
ENTRY_INSET = 48


class GeometryError(Exception):
    pass


def opposite_side(side: str) -> str:
    return {"left": "right", "right": "left", "top": "bottom", "bottom": "top"}[side]


class Monitor:
    __slots__ = ("x", "y", "w", "h", "scale")

    def __init__(self, x: int, y: int, w: int, h: int, scale: float = 1.0):
        self.x = int(x)
        self.y = int(y)
        self.w = int(w)
        self.h = int(h)
        self.scale = float(scale) or 1.0

    def to_dict(self) -> dict:
        return {"x": self.x, "y": self.y, "w": self.w, "h": self.h, "scale": self.scale}

    @classmethod
    def from_dict(cls, d: dict) -> "Monitor":
        try:
            return cls(d["x"], d["y"], d["w"], d["h"], float(d.get("scale", 1.0)))
        except (KeyError, TypeError, ValueError):
            raise GeometryError("malformed monitor dict")


class ScreenLayout:
    def __init__(self, monitors: list[Monitor], primary: int = 0):
        if not monitors:
            raise GeometryError("layout needs at least one monitor")
        self.monitors = list(monitors)
        self.primary = int(primary)

    # -- bounds ---------------------------------------------------------------

    @property
    def bounds(self) -> tuple[int, int, int, int]:
        xs = [m.x for m in self.monitors]
        ys = [m.y for m in self.monitors]
        return (min(xs), min(ys), max(xs), max(ys))

    def left(self) -> int:
        return min(m.x for m in self.monitors)

    def top(self) -> int:
        return min(m.y for m in self.monitors)

    def right(self) -> int:
        return max(m.x + m.w for m in self.monitors)

    def bottom(self) -> int:
        return max(m.y + m.h for m in self.monitors)

    def width(self) -> int:
        return self.right() - self.left()

    def height(self) -> int:
        return self.bottom() - self.top()

    def monitor_at(self, x: int, y: int) -> "Monitor | None":
        """The monitor containing (x, y), or None in empty union space.

        Edge-inclusive: a point exactly on a monitor's edge belongs to it
        (that is where the seam math runs).
        """
        for m in self.monitors:
            if m.x <= x <= m.x + m.w and m.y <= y <= m.y + m.h:
                return m
        return None

    # -- serialization --------------------------------------------------------

    def to_monitors(self) -> list[dict]:
        return [m.to_dict() for m in self.monitors]

    @classmethod
    def from_monitors(cls, monitors: list, primary: int = 0) -> "ScreenLayout":
        try:
            return cls([Monitor.from_dict(m) for m in monitors], primary)
        except (TypeError, ValueError):
            raise GeometryError("malformed monitor list")

    def edge_point(self, side: str, fraction: float) -> tuple[int, int]:
        """Point on this layout's ``side`` edge at the given fraction."""
        f = max(0.0, min(1.0, fraction))
        h = self.height() - 1
        w = self.width() - 1
        if side == "left":
            return self.left(), int(self.top() + f * h)
        if side == "right":
            return self.right() - 1, int(self.top() + f * h)
        if side == "top":
            return int(self.left() + f * w), self.top()
        if side == "bottom":
            return int(self.left() + f * w), self.bottom() - 1
        raise GeometryError(f"unknown side {side!r}")


def seam_fraction(layout: ScreenLayout, side: str, x: int, y: int) -> float:
    """0..1 position of (x, y) along the seam on ``side`` of ``layout``.

    The fraction maps against the monitor the point is actually in, so
    multiple monitors of different sizes each align proportionally along
    the seam segment they contribute.  Falls back to the union bounds for
    out-of-monitor coordinates (the peer mapping is union-based).
    """
    m = layout.monitor_at(x, y)
    if side in ("left", "right"):
        if m is not None:
            denom = (m.h - 1) or 1
            return max(0.0, min(1.0, (y - m.y) / denom))
        denom = (layout.height() - 1) or 1
        return max(0.0, min(1.0, (y - layout.top()) / denom))
    if side in ("top", "bottom"):
        if m is not None:
            denom = (m.w - 1) or 1
            return max(0.0, min(1.0, (x - m.x) / denom))
        denom = (layout.width() - 1) or 1
        return max(0.0, min(1.0, (x - layout.left()) / denom))
    raise GeometryError(f"unknown side {side!r}")


def _presses_outer_edge(layout: ScreenLayout, x: int, y: int, zone: int) -> str | None:
    """The real outer edge (x, y) presses against within ``zone`` px, or None.

    Inside a monitor the union edges are tested (they are always real
    outer edges: any monitor touching the union edge contributes that
    edge). A point in empty union space - the strips uneven monitor
    heights leave inside the OS-visible desktop - is never a seam. A
    point beyond the union entirely counts as pressing the edge it
    exited: real OSes clamp the cursor to the desktop, but test fakes
    and fast motion can overshoot, and a cursor 1 px past the wall is
    still "at" the wall.

    Corners return the horizontal side first (Input Leap behaviour);
    vertical is the fallback.
    """
    left, top, right, bottom = layout.left(), layout.top(), layout.right(), layout.bottom()
    horizontal = None
    if x <= left + zone:
        horizontal = "left"
    elif x >= right - 1 - zone:
        horizontal = "right"
    if horizontal is not None:
        return horizontal
    if y <= top + zone:
        return "top"
    if y >= bottom - 1 - zone:
        return "bottom"
    return None


def in_jump_zone(layout: ScreenLayout, x: int, y: int, zone: int = JUMP_ZONE) -> str | None:
    """The side whose edge (x, y) is within ``zone`` px, or None.

    Only real outer edges are seams: the point must be inside an actual
    monitor, or pressing beyond the union (see
    :func:`_presses_outer_edge`).  Uneven monitor heights leave strips of
    the union bounds that belong to no monitor (the OS lets the cursor
    park there), and the internal boundary between two of my own monitors
    is never a seam.
    """
    if layout.monitor_at(x, y) is None:
        if not _beyond_union(layout, x, y):
            return None
    return _presses_outer_edge(layout, x, y, zone)


def _beyond_union(layout: ScreenLayout, x: int, y: int) -> bool:
    return x < layout.left() or x > layout.right() - 1 or y < layout.top() or y > layout.bottom() - 1


def clamp_to_edge(layout: ScreenLayout, x: int, y: int, zone: int = JUMP_ZONE) -> tuple[int, int]:
    """Park (x, y) on the edge when inside a jump zone (prevents overshoot).

    Like :func:`in_jump_zone`, only real outer monitor edges count: a
    point in empty union space is left alone, a point beyond the union is
    pulled back inside.
    """
    if layout.monitor_at(x, y) is None and not _beyond_union(layout, x, y):
        return x, y
    left, top, right, bottom = layout.left(), layout.top(), layout.right(), layout.bottom()
    if x <= left + zone:
        x = left
    elif x >= right - 1 - zone:
        x = right - 1
    if y <= top + zone:
        y = top
    elif y >= bottom - 1 - zone:
        y = bottom - 1
    return x, y


def map_to_peer(peer_layout: ScreenLayout, my_side: str, fraction: float) -> tuple[int, int]:
    """Where the cursor lands on the peer for a seam on ``my_side``."""
    return peer_layout.edge_point(opposite_side(my_side), fraction)


def entry_point(peer_layout: ScreenLayout, my_side: str, fraction: float) -> tuple[int, int]:
    """A point just inside the peer's screen when crossing a shared edge.

    Landing exactly on the far screen's edge makes its return-edge detector
    immediately give control back.  Keep the pointer past the jump zone so a
    return only happens after the user intentionally moves back to the edge.
    """
    x, y = map_to_peer(peer_layout, my_side, fraction)
    inset = ENTRY_INSET
    peer_side = opposite_side(my_side)
    if peer_side == "left":
        x = min(peer_layout.right() - 1, x + inset)
    elif peer_side == "right":
        x = max(peer_layout.left(), x - inset)
    elif peer_side == "top":
        y = min(peer_layout.bottom() - 1, y + inset)
    else:  # bottom
        y = max(peer_layout.top(), y - inset)
    return x, y


def return_point(layout: ScreenLayout, my_side: str, fraction: float) -> tuple[int, int]:
    """Point just inside ``layout`` on ``my_side`` after control reverts.

    The seam point itself sits inside the jump zone, so the very next
    mouse move would re-hand the control over; keep the cursor past the
    jump zone so re-taking control requires an intentional move to the
    edge.
    """
    x, y = layout.edge_point(my_side, fraction)
    inset = JUMP_ZONE + 1
    if my_side == "left":
        x = min(layout.right() - 1, x + inset)
    elif my_side == "right":
        x = max(layout.left(), x - inset)
    elif my_side == "top":
        y = min(layout.bottom() - 1, y + inset)
    else:  # bottom
        y = max(layout.top(), y - inset)
    return x, y


def verify_topology(my_side: str, peer_side: str) -> bool:
    """Consistent iff both sides point the same pair of edges at each other."""
    return opposite_side(my_side) == peer_side


def pt_to_px(v: int, scale: float) -> int:
    return int(round(v * scale))


def px_to_pt(v: int, scale: float) -> int:
    return int(round(v / scale))
