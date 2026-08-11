"""The web server must shut down promptly on Ctrl+C.

uvicorn's timeout_graceful_shutdown defaults to None, meaning "wait forever
for open connections to close". The dashboard holds a websocket open for live
device updates, and that loop blocks on an unbounded queue get(), so the
connection never closes on its own -- leaving Ctrl+C hanging on
"Waiting for connections to close" until the user force-quits.
"""

import asyncio

import pytest


def test_graceful_shutdown_is_bounded():
    """A bounded timeout is what stops Ctrl+C hanging indefinitely."""
    from leetha.ui.web.app import WEB_SHUTDOWN_TIMEOUT

    assert WEB_SHUTDOWN_TIMEOUT is not None
    assert 0 < WEB_SHUTDOWN_TIMEOUT <= 30


def test_uvicorn_config_carries_the_timeout():
    import uvicorn

    from leetha.ui.web.app import WEB_SHUTDOWN_TIMEOUT, _build_uvicorn_config

    config = _build_uvicorn_config(
        app=lambda *a, **kw: None, host="127.0.0.1", port=8999,
        ssl_keyfile=None, ssl_certfile=None,
    )
    assert isinstance(config, uvicorn.Config)
    assert config.timeout_graceful_shutdown == WEB_SHUTDOWN_TIMEOUT


@pytest.mark.asyncio
async def test_next_event_returns_when_shutdown_is_signalled():
    """The websocket loop must wake on shutdown, not block on an idle queue.

    Without this the connection stays open through the whole drain period and
    uvicorn waits for it.
    """
    from leetha.ui.web.app import _next_event_or_shutdown

    queue: asyncio.Queue = asyncio.Queue()
    shutdown = asyncio.Event()

    async def _signal_soon():
        await asyncio.sleep(0.05)
        shutdown.set()

    asyncio.ensure_future(_signal_soon())
    event = await asyncio.wait_for(
        _next_event_or_shutdown(queue, shutdown), timeout=2.0
    )
    assert event is None  # None means "stop serving"


@pytest.mark.asyncio
async def test_next_event_still_delivers_events_normally():
    from leetha.ui.web.app import _next_event_or_shutdown

    queue: asyncio.Queue = asyncio.Queue()
    shutdown = asyncio.Event()
    await queue.put({"type": "device_update"})

    event = await asyncio.wait_for(
        _next_event_or_shutdown(queue, shutdown), timeout=2.0
    )
    assert event == {"type": "device_update"}


@pytest.mark.asyncio
async def test_already_shut_down_returns_immediately():
    from leetha.ui.web.app import _next_event_or_shutdown

    queue: asyncio.Queue = asyncio.Queue()
    shutdown = asyncio.Event()
    shutdown.set()

    event = await asyncio.wait_for(
        _next_event_or_shutdown(queue, shutdown), timeout=2.0
    )
    assert event is None


@pytest.mark.asyncio
async def test_watcher_signals_while_serving_not_after():
    """The event must be set when should_exit flips, not when serve() returns.

    Signalling from run_web_async's finally deadlocked: the drain waited on
    connections, and the connections waited on an event set only after the
    drain finished. The 3s timeout was the only thing breaking the circle.
    """
    from leetha.ui.web.app import _watch_server_exit

    class FakeServer:
        should_exit = False

    server = FakeServer()
    shutdown = asyncio.Event()
    watcher = asyncio.ensure_future(_watch_server_exit(server, shutdown, poll=0.01))

    await asyncio.sleep(0.05)
    assert not shutdown.is_set()          # still serving

    server.should_exit = True             # what one Ctrl+C does
    await asyncio.wait_for(shutdown.wait(), timeout=2.0)
    assert shutdown.is_set()
    watcher.cancel()


@pytest.mark.asyncio
async def test_streaming_endpoint_unblocks_once_the_watcher_fires():
    """End to end: an idle queue must release as soon as shutdown starts."""
    from leetha.ui.web.app import _watch_server_exit, _next_event_or_shutdown

    class FakeServer:
        should_exit = False

    server = FakeServer()
    shutdown = asyncio.Event()
    queue: asyncio.Queue = asyncio.Queue()   # deliberately never fed
    watcher = asyncio.ensure_future(_watch_server_exit(server, shutdown, poll=0.01))

    async def _flip():
        await asyncio.sleep(0.05)
        server.should_exit = True

    asyncio.ensure_future(_flip())
    event = await asyncio.wait_for(
        _next_event_or_shutdown(queue, shutdown), timeout=2.0
    )
    assert event is None
    watcher.cancel()


def test_uvicorn_does_not_steal_the_consoles_sigint_handler():
    """The console installs a two-stage Ctrl+C handler; uvicorn must not clobber it.

    uvicorn <=0.28 used install_signal_handlers(); 0.52 uses a capture_signals()
    context manager. Overriding only the former silently did nothing, so uvicorn
    replaced the console's handler and its force-quit path was unreachable --
    the first Ctrl+C then could not exit immediately.
    """
    import signal

    import uvicorn

    from leetha.ui.web.app import _release_uvicorn_signals

    server = uvicorn.Server(uvicorn.Config(lambda *a, **kw: None, port=9998))
    _release_uvicorn_signals(server)

    sentinel = signal.getsignal(signal.SIGINT)
    with server.capture_signals():
        assert signal.getsignal(signal.SIGINT) is sentinel
    assert signal.getsignal(signal.SIGINT) is sentinel


def test_request_immediate_shutdown_collapses_the_drain():
    """force_exit alone still waits: uvicorn awaits Server.wait_closed().

    A browser holding keep-alive connections never closes them, so shutdown
    burned the full graceful-shutdown timeout even with force_exit set. The
    timeout is read from config at that moment, so it has to be shrunk too.
    """
    import uvicorn

    from leetha.ui.web.app import WEB_SHUTDOWN_TIMEOUT, request_immediate_shutdown

    server = uvicorn.Server(uvicorn.Config(
        lambda *a, **kw: None, port=9997,
        timeout_graceful_shutdown=WEB_SHUTDOWN_TIMEOUT,
    ))
    assert server.config.timeout_graceful_shutdown == WEB_SHUTDOWN_TIMEOUT

    request_immediate_shutdown(server)

    assert server.should_exit is True
    assert server.force_exit is True
    assert server.config.timeout_graceful_shutdown == 0
