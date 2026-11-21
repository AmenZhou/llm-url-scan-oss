"""FastAPI app: the API contract: no exception text anywhere, docs off, 4 KiB cap, no id in the answer.

Every route catches its own exceptions and answers {"error": "<code>"} with no echo of the input; the class name of an unexpected error goes
to the log only. Advisory only: nothing acts on the answer.
"""
import asyncio
import json
import logging
import re
import sys
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .keys import caller_for
from .service import Refusal
from .urlcheck import UrlRejected, validate_url

BODY_CAP = 4096
SCHEDULER = "scheduler"      # caller label of the scheduler's token: /internal/recheck6 only, never /v1/scan
HEX64 = re.compile(r"[0-9a-f]{64}")


class NoExcFormatter(logging.Formatter):
    """Server logs never carry exception info or a stack."""

    def format(self, record):
        record.exc_info = record.exc_text = record.stack_info = None
        return super().format(record)


LOG_CONFIG = {
    "version": 1, "disable_existing_loggers": False,
    "formatters": {"plain": {"()": "llm_url_scan.app.NoExcFormatter", "fmt": "%(levelname)s %(name)s %(message)s"}},
    "handlers": {"default": {"class": "logging.StreamHandler", "formatter": "plain", "stream": "ext://sys.stderr"}},
    "loggers": {"uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
                "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
                "uvicorn.access": {"handlers": [], "level": "CRITICAL", "propagate": False}},
}


def install_excepthooks():
    """Any exception that escapes everything else prints its class name and nothing more."""
    def say(kind):
        print("unhandled %s" % kind, file=sys.stderr)
    sys.excepthook = lambda t, v, tb: say(t.__name__)
    threading.excepthook = lambda a: say(a.exc_type.__name__)


def _loop_handler(loop, ctx):
    exc = ctx.get("exception")
    print("loop error %s" % (type(exc).__name__ if exc else "none"), file=sys.stderr)


@asynccontextmanager
async def _lifespan(app):
    asyncio.get_running_loop().set_exception_handler(_loop_handler)
    yield


def create_app(service, callers):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)

    def err(code, status, caller=None, exc=None, retry_after=None):
        service.log.write("refusal", caller=caller, code=code, exc=exc)
        return JSONResponse({"error": code}, status_code=status, headers={"Retry-After": str(retry_after)} if retry_after else None)

    def who(request):
        h = request.headers.get("authorization", "")
        return caller_for(h[7:] if h.lower().startswith("bearer ") else "", callers)

    @app.exception_handler(RequestValidationError)
    async def _bad(request, exc):
        return err("bad_request", 400)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request, exc):
        return err({404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "internal"), exc.status_code if exc.status_code in (404, 405) else 500)

    @app.get("/healthz")
    async def healthz():
        return PlainTextResponse("ok")

    @app.get("/v1/status")
    async def status(request: Request):
        caller = None
        try:
            caller = who(request)
            return JSONResponse(service.status()) if caller else err("unauthorised", 401)
        except Exception as e:
            return err("internal", 500, caller, type(e).__name__)

    @app.post("/v1/scan")
    async def scan(request: Request):
        caller = None
        try:
            caller = who(request)
            if not caller or caller == SCHEDULER:
                return err("unauthorised", 401)
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > BODY_CAP:
                return err("too_large", 413, caller)
            body = b""
            async for chunk in request.stream():
                body += chunk
                if len(body) > BODY_CAP:
                    return err("too_large", 413, caller)
            try:
                obj = json.loads(body)
            except ValueError:
                return err("bad_request", 400, caller)
            if not isinstance(obj, dict) or set(obj) != {"url"} or not isinstance(obj["url"], str):
                return err("bad_request", 400, caller)
            try:
                return JSONResponse(await service.scan(obj["url"], caller))
            except UrlRejected:
                return err("url_not_allowed", 422, caller)
            except Refusal as r:
                return err(r.code, r.status, caller, retry_after=r.retry_after)
        except Exception as e:
            return err("internal", 500, caller, type(e).__name__)

    @app.post("/internal/recheck6")
    async def recheck6(request: Request):
        """The scheduler's token only. Logged only; the caller gets {"ok": true} and nothing about the page."""
        caller = None
        try:
            caller = who(request)
            if caller != SCHEDULER:
                return err("unauthorised", 401)
            body = await request.body()
            if len(body) > BODY_CAP:
                return err("too_large", 413, caller)
            try:
                obj = json.loads(body)
            except ValueError:
                return err("bad_request", 400, caller)
            if (not isinstance(obj, dict) or set(obj) != {"url", "hid", "salt_ver"} or not isinstance(obj["url"], str)
                    or not isinstance(obj["hid"], str) or not HEX64.fullmatch(obj["hid"]) or type(obj["salt_ver"]) is not int):
                return err("bad_request", 400, caller)
            try:
                validate_url(obj["url"])
            except UrlRejected:
                return err("url_not_allowed", 422, caller)
            await service.recheck6(obj["url"], obj["hid"], obj["salt_ver"])
            return JSONResponse({"ok": True})
        except Exception as e:
            return err("internal", 500, caller, type(e).__name__)

    return app
