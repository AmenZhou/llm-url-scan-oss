"""Local harmless test pages for the stack tests. Everything here is made up. Runs inside the compose test stack on fixture-net, port 8080.
Paths: /ok (long page with a form), /short (short page), /bank (made-up phishing-shaped bank login), /404, /403 (a bare wall), /hang (never answers in time), /redirect (302 to /ok)."""
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARK = "ZEBRAQUILL-9931"
OK = ("<html><head><title>Made up page</title></head><body><h1>Welcome to the made up page</h1>" + ("<p>This sentence is filler for the stack test. %s</p>" % MARK) * 40 +
      '<form action="/post" method="post"><input type="text" name="user"><input type="password" name="pw"><button type="submit">Go</button></form></body></html>')
SHORT = "<html><body><p>A tiny made up page. %s</p></body></html>" % MARK
# A made-up, phishing-shaped login for an invented bank on an unrelated host (the smoke run should hold it). No real brand.
BANK = ("<html><head><title>Brandx Bank - Secure Sign In</title></head><body><h1>Brandx Bank</h1>"
        "<p>Your Brandx Bank account has been suspended due to unusual activity. Verify your identity within 24 hours to avoid permanent closure.</p>"
        "<p>Enter your online banking ID, password and card number below to restore access. %s</p>"
        '<form action="/post" method="post"><input type="text" name="bankid" placeholder="Online banking ID">'
        '<input type="password" name="pw" placeholder="Password"><input type="text" name="card" placeholder="Card number">'
        '<button type="submit">Verify now</button></form></body></html>') % MARK


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, extra=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/ok":
            self._send(200, OK)
        elif p == "/short":
            self._send(200, SHORT)
        elif p == "/bank":
            self._send(200, BANK)
        elif p == "/404":
            self._send(404, "<html><body>Not here</body></html>")
        elif p == "/403":
            self._send(403, "<html><body>Forbidden</body></html>")
        elif p == "/redirect":
            self._send(302, "", [("Location", "/ok")])
        elif p == "/hang":
            time.sleep(40)
            self._send(200, OK)
        else:
            self._send(404, "<html><body>Not here</body></html>")


class S(ThreadingHTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    S(("0.0.0.0", 8080), H).serve_forever()
