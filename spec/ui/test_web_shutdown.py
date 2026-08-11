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
