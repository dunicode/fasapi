# uvicorn main:app --reload

import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

# --- Configuración ---
DATABASE_URL = "sqlite.db"
SECRET_KEY = "tu_clave_secreta_super_segura_cambiala_en_produccion"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 horas

security = HTTPBearer(auto_error=False)


# --- Gestión de Base de Datos SQLite ---
def get_db():
    conn = sqlite3.connect(DATABASE_URL, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Crea la tabla de usuarios si no existe."""
    with sqlite3.connect(DATABASE_URL) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializar la base de datos al arrancar
    init_db()
    yield


app = FastAPI(
    title="API de Autenticación",
    description="API con /register y /login usando SQLite en un solo archivo",
    version="1.0.0",
    lifespan=lifespan,
)


# --- Esquemas Pydantic ---
class UserAuth(BaseModel):
    email: EmailStr = Field(..., description="Correo electrónico del usuario")
    password: str = Field(..., min_length=6, description="Contraseña (mínimo 6 caracteres)")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str


class UserResponse(BaseModel):
    id: int
    email: str
    created_at: str


class MessageResponse(BaseModel):
    message: str


# --- Funciones de Seguridad ---
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    conn: sqlite3.Connection = Depends(get_db),
) -> sqlite3.Row:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido",
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado o inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    cursor = conn.cursor()
    cursor.execute("SELECT id, email, created_at FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )
    return user


# --- Rutas ---
@app.get("/", tags=["General"])
def read_root():
    return {
        "message": "Bienvenido a la API de autenticación",
        "docs": "/docs",
        "endpoints": ["/register", "/login", "/profile"],
    }


@app.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Autenticación"],
)
def register(user_data: UserAuth, conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    email = user_data.email.strip().lower()

    # Comprobar si el email ya existe
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El correo electrónico ya está registrado",
        )

    # Hashear contraseña y guardar usuario
    hashed_pwd = hash_password(user_data.password)
    cursor.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (email, hashed_pwd),
    )
    conn.commit()

    return {"message": f"Usuario con email '{email}' registrado exitosamente"}


@app.post(
    "/login",
    response_model=TokenResponse,
    tags=["Autenticación"],
)
def login(user_data: UserAuth, conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    email = user_data.email.strip().lower()

    cursor.execute(
        "SELECT id, email, password_hash FROM users WHERE email = ?",
        (email,),
    )
    user = cursor.fetchone()

    # Validar credenciales
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generar Token JWT
    token = create_access_token(data={"sub": user["email"]})

    return {
        "access_token": token,
        "token_type": "bearer",
        "email": user["email"],
    }


@app.get(
    "/profile",
    response_model=UserResponse,
    tags=["Usuarios"],
)
def read_current_user(current_user: sqlite3.Row = Depends(get_current_user)):
    """Endpoint protegido para comprobar que el token funciona."""
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "created_at": str(current_user["created_at"]),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
