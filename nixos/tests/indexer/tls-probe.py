"""Open one TLS connection and print how the server answered.

    tls-probe.py HOST PORT SERVER_NAME CA [CERT KEY] [--http]

Prints one line:
  refused <reason>   the handshake failed, or the server sent an alert or
                     closed the connection after it
  accepted <detail>  the server kept the connection open (transport), or
                     sent an HTTP status line (--http)

Exits 1 with "unreachable" if no TCP connection opens. A closed port is not
a TLS refusal, and a test must not pass on it.

With TLS 1.3 the server rejects a client certificate after the client
finished its half of the handshake. So the probe reads once: a rejection
arrives as an alert, an accepted transport client gets silence.
"""
import socket
import ssl
import sys

args = [a for a in sys.argv[1:] if a != "--http"]
http = "--http" in sys.argv
host, port, server_name, ca = args[:4]
context = ssl.create_default_context(cafile=ca)
# Python 3.13 sets VERIFY_X509_STRICT, which rejects the test CA: openssl
# req -x509 writes no keyUsage extension. curl and the JVM accept that CA.
context.verify_flags &= ~ssl.VERIFY_X509_STRICT
if len(args) == 6:
    context.load_cert_chain(args[4], args[5])

try:
    raw = socket.create_connection((host, int(port)), timeout=10)
except OSError as error:
    print(f"unreachable {error}")
    sys.exit(1)

try:
    with context.wrap_socket(raw, server_hostname=server_name) as tls:
        if http:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n".encode())
        tls.settimeout(5)
        try:
            data = tls.recv(256)
        except socket.timeout:
            print("accepted silence")
            sys.exit(0)
        if not data:
            print("refused closed")
        elif http:
            print("accepted " + data.split(b"\r\n", 1)[0].decode(errors="replace"))
        else:
            print(f"accepted {len(data)} bytes")
except (ssl.SSLError, ConnectionError) as error:
    print(f"refused {error}")
