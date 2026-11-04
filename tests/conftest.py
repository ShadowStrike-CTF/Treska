# Treska — shared pytest config.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

# F02: the apps only answer Host 127.0.0.1 / localhost (TrustedHostMiddleware).
# Starlette's TestClient defaults to Host "testserver", so point its default at
# loopback here instead of loosening the production allowlist. Runs at conftest
# import, before any test module builds a client.
from starlette.testclient import TestClient

_orig_init = TestClient.__init__


def _loopback_init(self, app, base_url="http://127.0.0.1", *args, **kwargs):
    _orig_init(self, app, base_url, *args, **kwargs)


TestClient.__init__ = _loopback_init
