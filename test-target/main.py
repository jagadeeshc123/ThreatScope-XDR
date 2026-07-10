from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

app = FastAPI(title="VulnScope Authorized Test Target")


@app.get("/", response_class=HTMLResponse)
def index():
    return Response(content="""
    <html><head><title>Authorized Test Target</title></head><body>
      <h1>VulnScope Scanner Test Target</h1>
      <p>This local service is intentionally configured for authorized scanner verification.</p>
      <a href="/login">Go to Login</a><br/>
      <a href="/mixed">Mixed Content Page</a>
    </body></html>
    """, media_type="text/html")


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return Response(content="""
    <html><body><h2>Login</h2><form action="/login" method="post">
      Username: <input type="text" name="user"><br/>
      Password: <input type="password" name="pwd"><br/>
      <input type="submit" value="Login">
    </form></body></html>
    """, media_type="text/html")


@app.get("/mixed", response_class=HTMLResponse)
def mixed_page():
    return Response(content='<html><body><h2>Mixed Content</h2><img src="http://example.invalid/image.jpg"></body></html>', media_type="text/html")


@app.get("/robots.txt")
def robots():
    return Response(content="User-agent: *\nDisallow: /admin\n", media_type="text/plain")


@app.get("/.env")
def test_env_file():
    return Response(content="TEST_VALUE=not_a_secret", media_type="text/plain")
