from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

app = FastAPI(title="VulnScope Demo Target")

@app.get("/", response_class=HTMLResponse)
def index():
    html_content = """
    <html>
        <head>
            <title>Demo Target</title>
        </head>
        <body>
            <h1>Welcome to the Demo Target</h1>
            <p>This is a safe target for VulnScope testing.</p>
            <a href="/login">Go to Login</a><br/>
            <a href="/mixed">Mixed Content Page</a>
        </body>
    </html>
    """
    return Response(content=html_content, media_type="text/html")

@app.get("/login", response_class=HTMLResponse)
def login_page():
    html_content = """
    <html>
        <body>
            <h2>Login</h2>
            <form action="/login" method="post">
                Username: <input type="text" name="user"><br/>
                Password: <input type="password" name="pwd"><br/>
                <input type="submit" value="Login">
            </form>
        </body>
    </html>
    """
    return Response(content=html_content, media_type="text/html")

@app.get("/mixed", response_class=HTMLResponse)
def mixed_page():
    html_content = """
    <html>
        <body>
            <h2>Mixed Content</h2>
            <img src="http://example.com/insecure-image.jpg" />
        </body>
    </html>
    """
    return Response(content=html_content, media_type="text/html")

@app.get("/robots.txt", response_class=HTMLResponse)
def robots():
    return Response(content="User-agent: *\nDisallow: /admin\n", media_type="text/plain")

@app.get("/.env", response_class=HTMLResponse)
def fake_env():
    return Response(content="DB_PASS=fake_password_for_demo_only", media_type="text/plain")

# Notice we explicitly do not add security headers like CSP or X-Frame-Options to trigger findings
