"""Test Web Application - Target for SOVA-WAF protection.

Runs on http://127.0.0.1:8080
Provides realistic HTTP endpoints for testing the WAF.
"""

from fastapi import FastAPI, Request, Query, Form
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime
import json

app = FastAPI(title="SOVA Test Application", version="0.1.0")


@app.get("/", response_class=HTMLResponse)
async def homepage():
    """Homepage endpoint."""
    return """
    <html>
    <head><title>SOVA Test App</title></head>
    <body>
        <h1>SOVA Test Application</h1>
        <p>This is the test application protected by SOVA-WAF.</p>
        <ul>
            <li><a href="/search?q=laptop">Search</a></li>
            <li><a href="/products">Products</a></li>
            <li><a href="/profile">Profile</a></li>
        </ul>
        <form action="/login" method="post">
            <input name="username" placeholder="Username">
            <input name="password" type="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """Login endpoint - accepts test credentials."""
    # Test credentials only
    valid_users = {
        "admin": "admin123",
        "user": "user123",
        "test": "test123",
    }

    if username in valid_users and valid_users[username] == password:
        return JSONResponse({
            "status": "success",
            "message": f"Welcome, {username}!",
            "session_id": f"sess_{username}_{datetime.utcnow().timestamp()}"
        })
    else:
        return JSONResponse({"status": "error", "message": "Invalid credentials"}, status_code=401)


@app.get("/search")
async def search(q: str = Query(default="")):
    """Search endpoint with query parameter."""
    # Simulated search results
    products = [
        {"id": 1, "name": "Laptop Pro", "price": 999.99},
        {"id": 2, "name": "Phone X", "price": 699.99},
        {"id": 3, "name": "Tablet Air", "price": 499.99},
        {"id": 4, "name": "Headphones Elite", "price": 199.99},
        {"id": 5, "name": "Smart Watch", "price": 299.99},
    ]

    results = [p for p in products if q.lower() in p["name"].lower()] if q else products

    return JSONResponse({
        "query": q,
        "results": results,
        "count": len(results)
    })


@app.get("/products")
async def products(id: int = Query(default=0)):
    """Product detail endpoint."""
    products_db = {
        10: {"id": 10, "name": "Laptop Pro 15", "price": 1299.99, "description": "High-performance laptop"},
        11: {"id": 11, "name": "Laptop Air 13", "price": 999.99, "description": "Lightweight laptop"},
        12: {"id": 12, "name": "Phone Pro Max", "price": 1199.99, "description": "Flagship smartphone"},
        20: {"id": 20, "name": "Gaming Console", "price": 499.99, "description": "Next-gen gaming"},
    }

    if id and id in products_db:
        return JSONResponse(products_db[id])
    elif id:
        return JSONResponse({"error": "Product not found"}, status_code=404)
    else:
        return JSONResponse({"products": list(products_db.values())})


@app.get("/profile")
async def profile():
    """User profile endpoint."""
    return JSONResponse({
        "user_id": 1,
        "username": "demo_user",
        "email": "demo@example.com",
        "role": "user",
        "last_login": datetime.utcnow().isoformat()
    })


@app.post("/upload")
async def upload(request: Request):
    """File upload endpoint."""
    body = await request.body()
    content_type = request.headers.get("content-type", "")
    return JSONResponse({
        "status": "received",
        "size": len(body),
        "content_type": content_type,
        "message": "File upload processed"
    })


@app.get("/download")
async def download():
    """File download endpoint."""
    return JSONResponse({
        "file": "sample.txt",
        "size": 1024,
        "download_url": "/download/files/sample.txt"
    })


@app.get("/redirect")
async def redirect(url: str = Query(default="/")):
    """Redirect endpoint (potential open redirect)."""
    from fastapi.responses import RedirectResponse
    # In production, validate URL. Here we just redirect.
    return RedirectResponse(url=url)


@app.get("/api/data")
async def api_data():
    """API data endpoint."""
    return JSONResponse({
        "data": [
            {"id": 1, "value": "sample_data_1"},
            {"id": 2, "value": "sample_data_2"},
            {"id": 3, "value": "sample_data_3"},
        ],
        "total": 3,
        "page": 1
    })


@app.get("/admin")
async def admin():
    """Admin endpoint - should be protected."""
    return JSONResponse({
        "message": "Admin panel",
        "users": ["admin", "user1", "user2"],
        "settings": {"debug": True, "version": "0.1.0"}
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
