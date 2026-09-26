# Treska web — FastAPI app and launcher. HTTP concerns only; no parsing logic lives here.
# © 2026 ShadowStrike. All rights reserved.
# Aut Viam Inveniam Aut Faciam

from __future__ import annotations

import dataclasses
import os
import shutil
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from treska.core.pipeline import parse_zip

PORT = 7332  # Sarissa 7331, Poligon 7333 — never reuse elsewhere.
HOST = "127.0.0.1"
URL = f"http://{HOST}:{PORT}"

_STATIC = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="Treska", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "port": PORT}

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC / "index.html", media_type="text/html")

    # Sync def: FastAPI runs it in its threadpool, so the blocking parse
    # doesn't stall the event loop.
    @app.post("/api/parse")
    def parse(file: UploadFile = File(...)) -> JSONResponse:
        fd, tmp_name = tempfile.mkstemp(prefix="treska_upload_", suffix=".zip")
        tmp_path = Path(tmp_name)
        try:
            # Close before parsing: Windows can't reopen a file that's still held open.
            with os.fdopen(fd, "wb") as tmp:
                shutil.copyfileobj(file.file, tmp)
            try:
                result = parse_zip(tmp_path)
            except ValueError as exc:
                # The message names the temp path; show the upload's name instead.
                msg = str(exc).replace(str(tmp_path), file.filename or "upload")
                return JSONResponse(status_code=422, content={"error": msg})
            except Exception:  # noqa: BLE001
                return JSONResponse(status_code=500, content={"error": "internal error"})
        finally:
            tmp_path.unlink(missing_ok=True)

        data = dataclasses.asdict(result)
        # Report the name the user uploaded, not the server-side temp path.
        data["zip_path"] = Path(file.filename or "upload.zip").name
        return JSONResponse(content=data)

    return app


def main() -> None:
    config = uvicorn.Config(create_app(), host=HOST, port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        print(f"treska: web server failed to start on {URL}")
        raise SystemExit(1)

    print(f"Treska web UI: {URL}  (Ctrl+C to stop)")
    webbrowser.open(URL)
    try:
        while thread.is_alive():
            thread.join(0.5)
    except KeyboardInterrupt:
        server.should_exit = True
        thread.join(5)


if __name__ == "__main__":
    main()
