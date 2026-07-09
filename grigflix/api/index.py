import os
from datetime import datetime, timedelta

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError
from passlib.context import CryptContext

# --------------------- CONFIGURAÇÕES ---------------------

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Defina a variável de ambiente SECRET_KEY.")

ALGORITHM = "HS256"
SESSION_EXPIRE_MINUTES = 60 * 24  # duração do login (1 dia), independente da validade da assinatura

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --------------------- BANCO DE DADOS ---------------------

def get_connection():
    dsn = os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("Defina a variável de ambiente POSTGRES_URL (Vercel Postgres).")
    return psycopg2.connect(dsn, sslmode="require", cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'user',
                    access_expires_at TIMESTAMP,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS movies (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    synopsis TEXT,
                    cover_url TEXT,
                    category VARCHAR(100),
                    year INTEGER,
                    video_url TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """)
        conn.commit()

        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1;")
            if cur.fetchone() is None:
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, role, access_expires_at, active)
                    VALUES (%s, %s, 'admin', NULL, TRUE)
                    ON CONFLICT (username) DO NOTHING;
                    """,
                    (ADMIN_USERNAME, pwd_context.hash(ADMIN_PASSWORD)),
                )
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ---- helpers de usuário ----

def db_get_user_by_username(username: str):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s;", (username,))
            return cur.fetchone()
    finally:
        conn.close()


def db_get_user_by_id(user_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
            return cur.fetchone()
    finally:
        conn.close()


def db_list_users():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users ORDER BY created_at DESC;")
            return cur.fetchall()
    finally:
        conn.close()


def db_create_user(username, password, role, access_expires_at, active=True):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role, access_expires_at, active)
                VALUES (%s, %s, %s, %s, %s);
                """,
                (username, pwd_context.hash(password), role, access_expires_at, active),
            )
        conn.commit()
    finally:
        conn.close()


def db_update_user(user_id, role, access_expires_at, active, password=None):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if password:
                cur.execute(
                    """
                    UPDATE users
                    SET role = %s, access_expires_at = %s, active = %s, password_hash = %s
                    WHERE id = %s;
                    """,
                    (role, access_expires_at, active, pwd_context.hash(password), user_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE users
                    SET role = %s, access_expires_at = %s, active = %s
                    WHERE id = %s;
                    """,
                    (role, access_expires_at, active, user_id),
                )
        conn.commit()
    finally:
        conn.close()


def db_renew_user(user_id, months):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT access_expires_at FROM users WHERE id = %s;", (user_id,))
            row = cur.fetchone()
            base = row["access_expires_at"] if row and row["access_expires_at"] and row["access_expires_at"] > datetime.utcnow() else datetime.utcnow()
            new_expiry = base + timedelta(days=30 * months)
            cur.execute(
                "UPDATE users SET access_expires_at = %s, active = TRUE WHERE id = %s;",
                (new_expiry, user_id),
            )
        conn.commit()
    finally:
        conn.close()


def db_delete_user(user_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
        conn.commit()
    finally:
        conn.close()


# ---- helpers de filmes ----

def db_list_movies():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM movies ORDER BY created_at DESC;")
            return cur.fetchall()
    finally:
        conn.close()


def db_get_movie(movie_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM movies WHERE id = %s;", (movie_id,))
            return cur.fetchone()
    finally:
        conn.close()


def db_create_movie(title, synopsis, cover_url, category, year, video_url):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO movies (title, synopsis, cover_url, category, year, video_url)
                VALUES (%s, %s, %s, %s, %s, %s);
                """,
                (title, synopsis, cover_url, category, year, video_url),
            )
        conn.commit()
    finally:
        conn.close()


def db_update_movie(movie_id, title, synopsis, cover_url, category, year, video_url):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE movies
                SET title = %s, synopsis = %s, cover_url = %s, category = %s, year = %s, video_url = %s
                WHERE id = %s;
                """,
                (title, synopsis, cover_url, category, year, video_url, movie_id),
            )
        conn.commit()
    finally:
        conn.close()


def db_delete_movie(movie_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM movies WHERE id = %s;", (movie_id,))
        conn.commit()
    finally:
        conn.close()


# --------------------- AUTENTICAÇÃO ---------------------

class NotAuthenticated(Exception):
    pass


class NotAuthorized(Exception):
    pass


@app.exception_handler(NotAuthenticated)
async def not_authenticated_handler(request: Request, exc: NotAuthenticated):
    resposta = RedirectResponse(url="/login")
    resposta.delete_cookie("access_token")
    return resposta


@app.exception_handler(NotAuthorized)
async def not_authorized_handler(request: Request, exc: NotAuthorized):
    return HTMLResponse("<h1>403 - Acesso negado</h1>", status_code=403)


def criar_token(username: str, role: str):
    expire = datetime.utcnow() + timedelta(minutes=SESSION_EXPIRE_MINUTES)
    to_encode = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise NotAuthenticated()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except JWTError:
        raise NotAuthenticated()

    user = db_get_user_by_username(username)
    if user is None or not user["active"]:
        raise NotAuthenticated()
    return user


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise NotAuthorized()
    return user


# --------------------- ROTAS PÚBLICAS ---------------------

@app.get("/")
async def root():
    return RedirectResponse(url="/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = db_get_user_by_username(username)
    erro = "Usuário ou senha incorretos."

    if user is None or not pwd_context.verify(password, user["password_hash"]):
        return templates.TemplateResponse(request, "login.html", {"error": erro})

    if not user["active"]:
        return templates.TemplateResponse(
            request, "login.html", {"error": "Usuário desativado. Fale com o administrador."}
        )

    token = criar_token(user["username"], user["role"])
    destino = "/admin/movies" if user["role"] == "admin" else "/dashboard"
    resposta = RedirectResponse(url=destino, status_code=302)
    resposta.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=SESSION_EXPIRE_MINUTES * 60,
    )
    return resposta


@app.get("/logout")
async def logout():
    resposta = RedirectResponse(url="/login")
    resposta.delete_cookie("access_token")
    return resposta


# --------------------- ÁREA DO USUÁRIO ---------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user=Depends(get_current_user)):
    if user["role"] == "admin":
        return RedirectResponse(url="/admin/movies")

    expira_em = user["access_expires_at"]
    acesso_valido = expira_em is not None and expira_em > datetime.utcnow()

    filmes = db_list_movies() if acesso_valido else []

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "username": user["username"],
            "acesso_valido": acesso_valido,
            "expira_em": expira_em,
            "filmes": filmes,
        },
    )


# --------------------- ÁREA ADMIN: FILMES ---------------------

@app.get("/admin", include_in_schema=False)
async def admin_root(user=Depends(require_admin)):
    return RedirectResponse(url="/admin/movies")


@app.get("/admin/movies", response_class=HTMLResponse)
async def admin_movies_list(request: Request, user=Depends(require_admin)):
    filmes = db_list_movies()
    return templates.TemplateResponse(
        request, "admin/movies.html", {"filmes": filmes, "username": user["username"], "active": "movies"}
    )


@app.get("/admin/movies/new", response_class=HTMLResponse)
async def admin_movie_new_form(request: Request, user=Depends(require_admin)):
    return templates.TemplateResponse(
        request, "admin/movie_form.html", {"filme": None, "username": user["username"], "active": "movies"}
    )


@app.post("/admin/movies/new")
async def admin_movie_new(
    title: str = Form(...),
    synopsis: str = Form(""),
    cover_url: str = Form(""),
    category: str = Form(""),
    year: int = Form(None),
    video_url: str = Form(""),
    user=Depends(require_admin),
):
    db_create_movie(title, synopsis, cover_url, category, year, video_url)
    return RedirectResponse(url="/admin/movies", status_code=303)


@app.get("/admin/movies/{movie_id}/edit", response_class=HTMLResponse)
async def admin_movie_edit_form(request: Request, movie_id: int, user=Depends(require_admin)):
    filme = db_get_movie(movie_id)
    if filme is None:
        raise HTTPException(status_code=404, detail="Filme não encontrado")
    return templates.TemplateResponse(
        request, "admin/movie_form.html", {"filme": filme, "username": user["username"], "active": "movies"}
    )


@app.post("/admin/movies/{movie_id}/edit")
async def admin_movie_edit(
    movie_id: int,
    title: str = Form(...),
    synopsis: str = Form(""),
    cover_url: str = Form(""),
    category: str = Form(""),
    year: int = Form(None),
    video_url: str = Form(""),
    user=Depends(require_admin),
):
    db_update_movie(movie_id, title, synopsis, cover_url, category, year, video_url)
    return RedirectResponse(url="/admin/movies", status_code=303)


@app.post("/admin/movies/{movie_id}/delete")
async def admin_movie_delete(movie_id: int, user=Depends(require_admin)):
    db_delete_movie(movie_id)
    return RedirectResponse(url="/admin/movies", status_code=303)


# --------------------- ÁREA ADMIN: USUÁRIOS ---------------------

@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_list(request: Request, user=Depends(require_admin)):
    usuarios = db_list_users()
    return templates.TemplateResponse(
        request,
        "admin/users.html",
        {"usuarios": usuarios, "username": user["username"], "agora": datetime.utcnow(), "active": "users"},
    )


@app.get("/admin/users/new", response_class=HTMLResponse)
async def admin_user_new_form(request: Request, user=Depends(require_admin)):
    return templates.TemplateResponse(
        request, "admin/user_form.html", {"usuario": None, "username": user["username"], "active": "users"}
    )


@app.post("/admin/users/new")
async def admin_user_new(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
    months: int = Form(1),
    user=Depends(require_admin),
):
    if db_get_user_by_username(username) is not None:
        return templates.TemplateResponse(
            request,
            "admin/user_form.html",
            {
                "usuario": None,
                "username": user["username"],
                "active": "users",
                "error": "Já existe um usuário com esse nome.",
            },
        )

    access_expires_at = None if role == "admin" else datetime.utcnow() + timedelta(days=30 * months)
    db_create_user(username, password, role, access_expires_at, active=True)
    return RedirectResponse(url="/admin/users", status_code=303)


@app.get("/admin/users/{user_id}/edit", response_class=HTMLResponse)
async def admin_user_edit_form(request: Request, user_id: int, user=Depends(require_admin)):
    usuario = db_get_user_by_id(user_id)
    if usuario is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return templates.TemplateResponse(
        request, "admin/user_form.html", {"usuario": usuario, "username": user["username"], "active": "users"}
    )


@app.post("/admin/users/{user_id}/edit")
async def admin_user_edit(
    user_id: int,
    role: str = Form("user"),
    password: str = Form(""),
    active: bool = Form(False),
    months: int = Form(0),
    user=Depends(require_admin),
):
    usuario = db_get_user_by_id(user_id)
    if usuario is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    access_expires_at = usuario["access_expires_at"]
    if role == "admin":
        access_expires_at = None
    elif months and months > 0:
        base = access_expires_at if access_expires_at and access_expires_at > datetime.utcnow() else datetime.utcnow()
        access_expires_at = base + timedelta(days=30 * months)

    db_update_user(user_id, role, access_expires_at, active, password=password or None)
    return RedirectResponse(url="/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/renew")
async def admin_user_renew(user_id: int, months: int = Form(1), user=Depends(require_admin)):
    db_renew_user(user_id, months)
    return RedirectResponse(url="/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/delete")
async def admin_user_delete(user_id: int, user=Depends(require_admin)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Você não pode excluir seu próprio usuário.")
    db_delete_user(user_id)
    return RedirectResponse(url="/admin/users", status_code=303)
