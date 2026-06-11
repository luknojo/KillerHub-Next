from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/search":
            term = query.get("q", [""])[0]
            self._html(f"<h1>Search</h1><p>Results for {term}</p>")
            return

        if parsed.path == "/item":
            item_id = query.get("id", [""])[0]
            body = "<h1>Item</h1>"
            if "'" in item_id or '"' in item_id:
                body += "<p>You have an error in your SQL syntax near the query.</p>"
            else:
                body += f"<p>Showing item {item_id}</p>"
            self._html(body)
            return

        self._html(
            """
            <h1>KillerHub test lab</h1>
            <a href="/search?q=test">Search</a>
            <a href="/item?id=1">Item</a>
            <form action="/search" method="GET">
              <input name="q">
              <button>Search</button>
            </form>
            """
        )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _html(self, body: str) -> None:
        content = f"""<!doctype html>
<html>
<head>
  <meta name="generator" content="KillerHub Lab">
  <script src="/static/jquery.js"></script>
  <link rel="stylesheet" href="/static/bootstrap.css">
</head>
<body>{body}</body>
</html>""".encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("x-powered-by", "Python")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8088), Handler)
    print("Lab running at http://127.0.0.1:8088")
    server.serve_forever()
