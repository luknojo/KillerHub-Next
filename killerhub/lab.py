from __future__ import annotations

import sqlite3

from flask import Flask, Response, make_response, redirect, render_template_string, request


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "killerhub-lab-dev-key"
    _init_db()

    @app.get("/")
    def home() -> str:
        return render_template_string(
            LAB_LAYOUT,
            title="KillerShop",
            body="""
            <section class="hero">
              <div>
                <p class="eyebrow">Local training lab</p>
                <h1>KillerShop</h1>
                <p>A tiny storefront with intentionally vulnerable search, item, login, and feedback flows.</p>
              </div>
              <form action="/search" method="get" class="search">
                <input name="q" placeholder="Search products">
                <button>Search</button>
              </form>
            </section>
            <section class="grid">
              <a class="card" href="/item?id=1"><span>01</span><strong>USB Rubber Duck</strong><small>Item lookup</small></a>
              <a class="card" href="/item?id=2"><span>02</span><strong>Packet Hoodie</strong><small>Reflected parameter</small></a>
              <a class="card" href="/login"><span>03</span><strong>Member Login</strong><small>SQL error path</small></a>
              <a class="card" href="/feedback"><span>04</span><strong>Feedback</strong><small>Stored-style demo</small></a>
            </section>
            <section class="panel">
              <h2>Connected services</h2>
              <p><a href="http://api.killershop.local/v1/products">Product API</a></p>
              <p><a href="http://auth.killershop.local/login">SSO portal</a></p>
              <form action="http://payments.killershop.local/checkout" method="post" class="search">
                <input name="coupon" placeholder="Coupon code">
                <button>Preview checkout</button>
              </form>
            </section>
            """,
        )

    @app.get("/search")
    def search() -> str:
        query = request.args.get("q", "")
        return render_template_string(
            LAB_LAYOUT,
            title="Search",
            body=f"""
            <section class="panel">
              <h1>Search</h1>
              <form action="/search" method="get" class="search">
                <input name="q" value="{query}" placeholder="Search products">
                <button>Search</button>
              </form>
              <p class="result">Results for {query}</p>
              <a href="/item?id={query or '1'}">Open matching item</a>
            </section>
            """,
        )

    @app.get("/item")
    def item() -> str:
        item_id = request.args.get("id", "1")
        error = ""
        if "'" in item_id or '"' in item_id or ")" in item_id:
            error = "<p class='danger'>You have an error in your SQL syntax near the item query.</p>"
        return render_template_string(
            LAB_LAYOUT,
            title="Item",
            body=f"""
            <section class="panel">
              <h1>Item #{item_id}</h1>
              <p>Inventory record loaded for product id {item_id}.</p>
              {error}
              <form action="/item" method="get" class="search">
                <input name="id" value="{item_id}">
                <button>Load</button>
              </form>
            </section>
            """,
        )

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str | Response:
        message = ""
        username = ""
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            try:
                query = f"select username from users where username = '{username}' and password = '{password}'"
                row = sqlite3.connect("lab.db").execute(query).fetchone()
                message = f"Welcome {row[0]}" if row else "Invalid credentials"
            except sqlite3.Error as exc:
                message = f"SQLite error: {exc}"

        return render_template_string(
            LAB_LAYOUT,
            title="Login",
            body=f"""
            <section class="panel narrow">
              <h1>Login</h1>
              <form method="post" class="stack">
                <input name="username" value="{username}" placeholder="Username">
                <input name="password" type="password" placeholder="Password">
                <button>Sign in</button>
              </form>
              <p class="result">{message}</p>
            </section>
            """,
        )

    @app.route("/feedback", methods=["GET", "POST"])
    def feedback() -> str | Response:
        if request.method == "POST":
            response = make_response(redirect("/feedback"))
            response.set_cookie("lab_session", request.form.get("name", "guest"))
            return response
        name = request.cookies.get("lab_session", "guest")
        return render_template_string(
            LAB_LAYOUT,
            title="Feedback",
            body=f"""
            <section class="panel narrow">
              <h1>Feedback</h1>
              <form method="post" class="stack">
                <input name="name" placeholder="Name">
                <textarea name="message" placeholder="Message"></textarea>
                <button>Send</button>
              </form>
              <p class="result">Last visitor: {name}</p>
            </section>
            """,
        )

    @app.get("/static/<path:name>")
    def fake_static(name: str) -> Response:
        if name.endswith(".js"):
            return Response("window.KillerShop = { framework: 'jquery' };", mimetype="application/javascript")
        return Response("body{--lab-theme:bootstrap;}", mimetype="text/css")

    return app


def run(host: str = "127.0.0.1", port: int = 8088) -> None:
    create_app().run(host=host, port=port, debug=False)


def _init_db() -> None:
    conn = sqlite3.connect("lab.db")
    conn.execute("create table if not exists users (username text, password text)")
    conn.execute("delete from users")
    conn.execute("insert into users values ('student', 'killerhub')")
    conn.commit()
    conn.close()


LAB_LAYOUT = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="KillerShop Lab">
  <title>{{ title }}</title>
  <script src="/static/jquery.js"></script>
  <script src="http://cdn.killershop.local/assets/tracker.js"></script>
  <link rel="stylesheet" href="/static/bootstrap.css">
  <link rel="stylesheet" href="http://static.killershop.local/theme.css">
  <style>
    :root { color-scheme: light; font-family: Inter, Segoe UI, Arial, sans-serif; }
    body { margin: 0; background: #f7f7f4; color: #202124; }
    header { height: 56px; display: flex; align-items: center; justify-content: space-between; padding: 0 28px; border-bottom: 1px solid #dedbd2; background: #ffffff; }
    header a { color: #202124; text-decoration: none; margin-left: 18px; font-size: 14px; }
    main { max-width: 1080px; margin: 0 auto; padding: 34px 22px; }
    h1 { margin: 0 0 12px; font-size: 42px; line-height: 1.05; }
    .hero { min-height: 360px; display: grid; grid-template-columns: 1.2fr .8fr; gap: 28px; align-items: center; }
    .eyebrow { text-transform: uppercase; font-size: 12px; letter-spacing: .12em; color: #60646c; }
    .search, .stack { display: grid; gap: 10px; }
    .search { grid-template-columns: 1fr auto; }
    input, textarea { border: 1px solid #c8c4b8; border-radius: 6px; padding: 11px 12px; font: inherit; background: #fff; }
    textarea { min-height: 110px; resize: vertical; }
    button { border: 0; border-radius: 6px; padding: 11px 16px; font: inherit; color: #fff; background: #0f766e; cursor: pointer; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
    .card, .panel { background: #fff; border: 1px solid #dedbd2; border-radius: 8px; box-shadow: 0 12px 26px rgba(32, 33, 36, .06); }
    .card { min-height: 126px; padding: 18px; color: inherit; text-decoration: none; display: grid; align-content: space-between; }
    .card span, small { color: #6b7280; }
    .panel { padding: 24px; }
    .narrow { max-width: 520px; }
    .result { padding: 12px; background: #eef7f5; border-radius: 6px; }
    .danger { padding: 12px; background: #fee2e2; color: #991b1b; border-radius: 6px; }
    @media (max-width: 760px) {
      .hero, .grid { grid-template-columns: 1fr; }
      .search { grid-template-columns: 1fr; }
      h1 { font-size: 34px; }
    }
  </style>
</head>
<body>
  <header>
    <strong>KillerShop</strong>
    <nav><a href="/">Home</a><a href="/search?q=hoodie">Search</a><a href="/login">Login</a><a href="/feedback">Feedback</a></nav>
  </header>
  <main>{{ body|safe }}</main>
</body>
</html>"""
