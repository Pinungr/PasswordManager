import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import SQLAlchemyError

from app.api.admin import router as admin_router
from app.api.auth import dummy_password_hash
from app.api.auth import router as auth_router
from app.api.backups import router as backups_router
from app.api.catalog import router as catalog_router
from app.api.personal import payload_limit
from app.api.personal import router as personal_router
from app.api.rotation import router as rotation_router
from app.api.settings import load_policy
from app.api.settings import router as settings_router
from app.api.shared import router as shared_router
from app.bootstrap import bootstrap_from_environment
from app.core.config import Settings
from app.database.backups import BackupStorage
from app.database.connection import make_engine
from app.database.maintenance import maintenance
from app.database.migrate import ALEMBIC_CONFIG, migrate
from app.security.accounts import audit, write

VERSION = "1.0.0"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; worker-src 'self'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
)


class RequestLimit:
    def __init__(self, app, max_bytes, record_max_bytes):
        self.app = app
        self.max_bytes = max_bytes
        self.record_max_bytes = record_max_bytes
        self.large_requests = asyncio.Semaphore(4)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return
        path = scope["path"]
        large_record = (
            scope["method"] == "PUT"
            and (
                path.startswith("/api/v1/personal/records/")
                or (path.startswith("/api/v1/shared/vaults/") and "/records" in path)
            )
        ) or (
            scope["method"] == "POST"
            and path.startswith("/api/v1/shared/vaults/")
            and "/rotation/" in path
            and path.endswith("/finish")
        )
        if not large_record:
            await self.forward(scope, receive, send, self.max_bytes)
            return
        small_limit = min(self.record_max_bytes, 262144)
        declared = [value for name, value in scope["headers"] if name == b"content-length"]
        if (
            len(declared) == 1
            and declared[0].isdigit()
            and len(declared[0]) <= 12
            and int(declared[0]) <= small_limit
        ):
            await self.forward(scope, receive, send, small_limit)
            return
        if self.large_requests.locked():
            await JSONResponse(
                {"detail": "Storage is busy. Try again."}, 503, headers={"Retry-After": "1"}
            )(scope, receive, send)
            return
        async with self.large_requests:
            await self.forward(scope, receive, send, self.record_max_bytes)

    async def forward(self, scope, receive, send, max_bytes):
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > max_bytes:
                await JSONResponse(
                    {"detail": "Request is too large."}, 413, headers={"Cache-Control": "no-store"}
                )(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body"):
                break

        delivered = False

        async def buffered():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, buffered, send)


def create_app(
    settings: Settings,
    database_path: Path,
    database_key: str,
    frontend: Path,
    audit_key: bytes,
    backups: BackupStorage | None = None,
):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        restored = False
        if backups:
            head = ScriptDirectory.from_config(Config(str(ALEMBIC_CONFIG))).get_current_head()
            restored = backups.apply(head)
        engine = make_engine(database_path, database_key)
        try:
            app.state.revision = migrate(engine)
            app.state.engine = engine
            app.state.backups = backups
            if restored:
                with write(engine) as connection:
                    audit(connection, audit_key, "backup.restore")
            app.state.settings = load_policy(engine, settings)
            app.state.audit_key = audit_key
            bootstrap_from_environment(engine, app.state.settings, audit_key)
            app.state.dummy_hash = dummy_password_hash()
            stop = asyncio.Event()
            task = asyncio.create_task(maintenance(engine, app.state, stop))
            try:
                yield
            finally:
                stop.set()
                await task
        finally:
            engine.dispose()

    app = FastAPI(
        title=settings.app_name,
        version=VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        telemetry={
            "tracing": False,
            "metrics": False,
            "logs": False,
            "operation_spans": False,
            "auto_configure": False,
        },
    )
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(personal_router)
    app.include_router(catalog_router)
    app.include_router(shared_router)
    app.include_router(rotation_router)
    app.include_router(settings_router)
    app.include_router(backups_router)
    app.add_middleware(
        RequestLimit, max_bytes=16384, record_max_bytes=payload_limit(settings) + 512
    )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _error: RequestValidationError):
        return JSONResponse({"detail": "Check the submitted fields."}, status_code=422)

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.headers.getlist("host") != [settings.authority]:
            response = JSONResponse({"detail": "Invalid host"}, status_code=400)
        elif request.url.scheme != "https":
            response = JSONResponse({"detail": "HTTPS required"}, status_code=400)
        elif (
            backups
            and request.method not in {"GET", "HEAD"}
            and request.url.path.startswith("/api/v1/")
            and request.url.path != "/api/v1/auth/logout"
            and backups.staging.exists()
        ):
            response = JSONResponse(
                {"detail": "A database restore is staged. Restart to continue."}, status_code=503
            )
        else:
            response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health/live", include_in_schema=False)
    def liveness():
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def readiness():
        try:
            with app.state.engine.connect() as connection:
                revision = connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version"
                ).scalar_one()
                instance = connection.exec_driver_sql(
                    "SELECT format_version FROM application_instance WHERE id = 1"
                ).scalar_one()
                if revision == app.state.revision and instance == 1:
                    return {"status": "ok"}
        except SQLAlchemyError:
            pass
        return JSONResponse({"status": "unavailable"}, status_code=503)

    @app.get("/api/v1/info")
    def info():
        return {"name": settings.app_name, "version": VERSION, "theme": settings.default_theme}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(frontend / "index.html")

    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")

    return app
