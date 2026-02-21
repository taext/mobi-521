#!/usr/bin/env python3
"""
Simple HTTPS server for serving the mobi-521 web UI.
Requires SSL certificates in the same directory.
"""
import http.server
import ssl
import sys
from pathlib import Path

PORT = 443
CERTFILE = "cert.pem"
KEYFILE = "key.pem"

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add security headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')

        # Prevent aggressive caching
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')

        super().end_headers()

def main():
    # Change to web directory
    web_dir = Path(__file__).parent

    handler = MyHTTPRequestHandler

    # Create HTTPS server
    httpd = http.server.HTTPServer(("0.0.0.0", PORT), handler)

    # Setup SSL
    cert_path = web_dir / CERTFILE
    key_path = web_dir / KEYFILE

    if not cert_path.exists() or not key_path.exists():
        print(f"Error: SSL certificates not found!")
        print(f"Expected: {cert_path} and {key_path}")
        print(f"\nGenerate self-signed cert with:")
        print(f"  openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365")
        sys.exit(1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Serving HTTPS on https://0.0.0.0:{PORT}/")
    print(f"Serving from: {web_dir}")
    print("Press Ctrl+C to stop")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.shutdown()

if __name__ == "__main__":
    main()
