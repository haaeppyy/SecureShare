"""Share IPC: Finder/Explorer 'share' flows into the running tray app.

The picker aggregation and forwarding are covered here; the tkinter dialog
itself is skipped headlessly (records the batch on the app instead).
"""

import json
import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tray.app as appmod  # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_share_files_from_url_decodes_paths():
    url = "secureshare://send?files=a%20b%2Fc%0Ad"
    assert appmod.share_files_from_url(url) == ["a b/c", "d"]
    assert appmod.share_files_from_url("secureshare://other?files=x") == []
    assert appmod.share_files_from_url("http://send?files=x") == []


def test_parse_share_argv_shapes():
    url = "secureshare://send?files=a%20b%0Ac"
    rest, files = appmod.parse_share_argv(
        [url, "-sendFile", "/x/y.txt", "-psn_1234", "--port", "48621", "/z/q.txt"]
    )
    # Plain paths stay for argparse's positional 'files'.
    assert rest == ["--port", "48621", "/z/q.txt"]
    assert files == ["a b", "c", "/x/y.txt"]


def test_forward_refused_when_no_primary(monkeypatch):
    monkeypatch.setattr(appmod, "SHARE_IPC_PORT", _free_port())
    assert appmod.forward_share_request(["x"]) is False


def test_forward_reaches_primary_and_gets_ok(monkeypatch):
    port = _free_port()
    monkeypatch.setattr(appmod, "SHARE_IPC_PORT", port)
    received = {}

    def server():
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.listen(1)
        conn, _ = s.accept()
        data = conn.recv(65536)
        received["req"] = json.loads(data.decode("utf-8"))
        conn.sendall(b"ok")
        conn.close()
        s.close()

    t = threading.Thread(target=server, daemon=True)
    t.start()
    assert appmod.forward_share_request(["/tmp/a", "/tmp/b"]) is True
    t.join(timeout=2)
    assert received["req"] == {"action": "share", "files": ["/tmp/a", "/tmp/b"]}


def test_start_ipc_receives_forwarded_request(monkeypatch, tmp_path):
    port = _free_port()
    monkeypatch.setattr(appmod, "SHARE_IPC_PORT", port)
    real_file = tmp_path / "payload.txt"
    real_file.write_text("hello")
    app = appmod.TrayApp()
    app.node = type(
        "Node",
        (),
        {"store": type("Store", (), {"list_peers": lambda self: []})()},
    )()
    app._start_share_ipc()
    try:
        assert app._share_ipc is not None, "must bind as primary"
        assert appmod.forward_share_request([str(real_file)]) is True
        fn, args = app._queue.get(timeout=3)
        assert fn.__func__ is app._queue_share_files.__func__
        assert args == ([str(real_file)],)
        fn(*args)
        assert app._share_pending == [str(real_file)]
    finally:
        app._stopping = True
        ipc = app._share_ipc
        app._share_ipc = None
        if ipc is not None:
            ipc.close()


def test_forward_is_noop_when_secondary_starts(monkeypatch):
    # A second instance that cannot bind just stays a client; the primary
    # binds once. Two binds: one wins, the other gets OSError -> None.
    monkeypatch.setattr(appmod, "SHARE_IPC_PORT", _free_port())
    app = appmod.TrayApp()
    app._start_share_ipc()
    try:
        other = appmod.TrayApp()
        other._start_share_ipc()
        assert (app._share_ipc is not None) != (other._share_ipc is not None)
        if other._share_ipc is not None:
            other._stopping = True
            other._share_ipc.close()
    finally:
        if app._share_ipc is not None:
            app._stopping = True
            app._share_ipc.close()


pytestmark = pytest.mark.socket