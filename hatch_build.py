"""Build hook that keeps source installs working without a built frontend.

The compiled dashboard is committed to the repository, so a normal clone
already ships a working UI and this hook does nothing. It exists for trees
where ``src/leetha/ui/web/dist`` is missing -- deleted, or never generated in
a checkout that predates it being committed -- so the wheel still builds and
installs instead of failing.

When a real build is present it is left untouched; otherwise a placeholder
page is written that explains how to produce the real UI. The CLI, capture
engine, and API are unaffected either way.
"""

from __future__ import annotations

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_DIST_REL = "src/leetha/ui/web/dist"

_PLACEHOLDER = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Leetha — dashboard not built</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           margin: 0; display: grid; place-items: center; min-height: 100vh; }
    main { max-width: 40rem; padding: 2rem; line-height: 1.6; }
    h1 { font-size: 1.4rem; margin-bottom: .5rem; }
    code, pre { background: #1e293b; border-radius: 6px; }
    code { padding: .1rem .35rem; }
    pre { padding: 1rem; overflow-x: auto; }
    a { color: #38bdf8; }
  </style>
</head>
<body>
  <main>
    <h1>Leetha is running, but the dashboard was not bundled</h1>
    <p>
      This copy was installed from source without a compiled frontend, so the
      web UI is a placeholder. Everything else &mdash; capture, fingerprinting,
      the CLI, and the REST API &mdash; works normally.
    </p>
    <p>To build the real dashboard:</p>
    <pre>git clone https://github.com/tjnull/leetha.git
cd leetha/frontend &amp;&amp; bun install &amp;&amp; bun run build
cd .. &amp;&amp; pipx install --force .</pre>
    <p>
      The API is available now &mdash; try
      <a href="/api/stats">/api/stats</a> or <a href="/health">/health</a>.
    </p>
  </main>
</body>
</html>
"""


class CustomBuildHook(BuildHookInterface):
    """Ensure the force-included frontend directory always exists."""

    def initialize(self, version, build_data):  # noqa: ARG002 - hatchling API
        dist = Path(self.root) / _DIST_REL
        index = dist / "index.html"

        if index.is_file() and index.stat().st_size > 0:
            return  # A real build is present; leave it alone.

        dist.mkdir(parents=True, exist_ok=True)
        index.write_text(_PLACEHOLDER, encoding="utf-8")
