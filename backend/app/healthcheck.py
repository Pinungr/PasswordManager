import http.client
import os
import socket
import ssl

from app.core.config import load_settings


def main() -> None:
    settings = load_settings()
    port = int(os.environ.get("SECUREVAULT_INTERNAL_PORT", str(settings.https_port)))
    context = ssl.create_default_context(cafile=os.environ["SECUREVAULT_TLS_CA_FILE"])
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as connection,
        context.wrap_socket(connection, server_hostname=settings.hostname) as tls,
    ):
        request = (
            f"GET /health/ready HTTP/1.1\r\nHost: {settings.authority}\r\nConnection: close\r\n\r\n"
        )
        tls.sendall(request.encode("ascii"))
        with http.client.HTTPResponse(tls) as response:
            response.begin()
            if response.status != 200:
                raise SystemExit(1)


if __name__ == "__main__":
    main()
