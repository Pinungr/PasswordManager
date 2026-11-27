import http.client
import os
import socket
import ssl
from contextlib import nullcontext
from pathlib import Path

from app.core.config import load_settings
from app.core.tls import tls_paths


def main() -> None:
    settings = load_settings()
    port = int(os.environ.get("SECUREVAULT_INTERNAL_PORT", str(settings.https_port)))
    context = None
    if settings.protocol == "https":
        data = Path(os.environ.get("SECUREVAULT_DATA_DIR", "/data"))
        _, _, ca = tls_paths(data, settings.host_mode)
        context = ssl.create_default_context(cafile=ca)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        transport = (
            context.wrap_socket(connection, server_hostname=settings.hostname)
            if context else nullcontext(connection)
        )
        with transport as stream:
            request = (
                f"GET /health/ready HTTP/1.1\r\nHost: {settings.authority}\r\nConnection: close\r\n\r\n"
            )
            stream.sendall(request.encode("ascii"))
            with http.client.HTTPResponse(stream) as response:
                response.begin()
                if response.status != 200:
                    raise SystemExit(1)


if __name__ == "__main__":
    main()
