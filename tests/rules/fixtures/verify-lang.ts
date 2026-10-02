import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
// Fake credentials assembled at runtime so secret scanners do not flag this file.
const AWS_KEY = ['AKIA', 'QYLPMN5HHHFPZAM2'].join('');
const DB_PASS = ['Xk9', 'v2Lq', '7Rw'].join('');
const PEM_HEAD = ['-----BEGIN', 'RSA PRIVATE KEY-----'].join(' ');
const PEM_TAIL = ['-----END', 'RSA PRIVATE KEY-----'].join(' ');
const PEM_BODY = 'MIIEowIBAAKCAQEAu7Jx3k9QwZs2f1y0d8nV5pLr' + 'T4mH6cB2qWzYxK8eJ0aFgN3hD9sLvU1oR7iPtMbC';

/** Python (FastAPI / Flask / Django), Go (net/http, Gin), PHP / Laravel, Java, C#, Ruby / Rails. */
export const CASES: RuleCase[] = [
  // ---------------------------------------------------------------- Python
  {
    ruleIds: [8806],
    name: 'FastAPI CORSMiddleware wildcard origin with credentials',
    detects: f('app/main.py', `from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
`),
    ignores: f('app/main.py', `from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin).strip("/") for origin in settings.all_cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
`)
  },
  {
    ruleIds: [8807],
    name: 'FastAPI async handler calling blocking requests.get',
    detects: f('app/api/routes/weather.py', `import requests
from fastapi import APIRouter

router = APIRouter()


@router.get("/weather/{city}")
async def get_weather(city: str):
    resp = requests.get(f"https://api.weather.example/v1/{city}", timeout=5)
    return resp.json()
`),
    ignores: f('app/api/routes/weather.py', `import httpx
import requests
from fastapi import APIRouter

router = APIRouter()


@router.get("/weather/{city}")
async def get_weather(city: str):
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(f"https://api.weather.example/v1/{city}")
    return resp.json()


def sync_forecast(city: str):
    return requests.get(f"https://api.weather.example/v1/{city}/forecast", timeout=5).json()
`)
  },
  {
    ruleIds: [8808],
    name: 'Celery configured with pickle serializer',
    detects: f('app/worker.py', `from celery import Celery

celery_app = Celery("worker", broker="redis://redis:6379/0")
celery_app.conf.update(
    task_serializer="pickle",
    accept_content=["json", "pickle"],
    result_serializer="pickle",
)
`),
    ignores: f('app/worker.py', `from celery import Celery

celery_app = Celery("worker", broker="redis://redis:6379/0")
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
)
`)
  },
  {
    ruleIds: [8810],
    name: 'Flask render_template_string with user input in the template',
    detects: f('app/views.py', `from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template_string(f"<h1>Hello {name}!</h1>")
`),
    ignores: f('app/views.py', `from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)
`)
  },
  {
    ruleIds: [8813],
    name: 'tempfile.mktemp race-prone temp file',
    detects: f('app/services/export.py', `import tempfile


def write_export(rows):
    path = tempfile.mktemp(suffix=".csv")
    with open(path, "w") as fh:
        fh.writelines(rows)
    return path
`),
    ignores: f('app/services/export.py', `import tempfile


def write_export(rows):
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
        fh.writelines(rows)
        return fh.name
`)
  },
  {
    ruleIds: [8815],
    name: 'lxml parser with external entity resolution enabled',
    detects: f('app/api/invoices.py', `from fastapi import APIRouter, Request
from lxml import etree

router = APIRouter()


@router.post("/invoices/import")
async def import_invoice(request: Request):
    body = await request.body()
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    doc = etree.fromstring(body, parser)
    return {"total": doc.findtext("total")}
`),
    ignores: f('app/api/invoices.py', `from fastapi import APIRouter, Request
from lxml import etree

router = APIRouter()


@router.post("/invoices/import")
async def import_invoice(request: Request):
    body = await request.body()
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    doc = etree.fromstring(body, parser)
    return {"total": doc.findtext("total")}
`)
  },
  {
    ruleIds: [8816],
    name: 'Flask download opens a path built from a query parameter',
    detects: f('app/downloads.py', `import os

from flask import Flask, request, Response

app = Flask(__name__)
REPORT_DIR = "/srv/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("file")
    with open(os.path.join(REPORT_DIR, filename), "rb") as fh:
        return Response(fh.read(), mimetype="application/pdf")
`),
    ignores: f('app/downloads.py', `import os

from flask import Flask, request, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)
REPORT_DIR = "/srv/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("file")
    with open(os.path.join(REPORT_DIR, secure_filename(filename)), "rb") as fh:
        return Response(fh.read(), mimetype="application/pdf")
`)
  },
  {
    ruleIds: [8818],
    name: 'requests call with TLS verification disabled',
    detects: f('app/integrations/billing.py', `import requests


def fetch_invoices(api_url: str, token: str):
    resp = requests.get(f"{api_url}/invoices", headers={"Authorization": f"Bearer {token}"}, verify=False)
    resp.raise_for_status()
    return resp.json()
`),
    ignores: f('app/integrations/billing.py', `import requests


def fetch_invoices(api_url: str, token: str):
    resp = requests.get(f"{api_url}/invoices", headers={"Authorization": f"Bearer {token}"}, timeout=10)
    resp.raise_for_status()
    return resp.json()
`)
  },
  {
    ruleIds: [8819],
    name: 'marshal.loads on request body',
    detects: f('app/sync.py', `import marshal

from flask import Flask, request

app = Flask(__name__)


@app.route("/sync", methods=["POST"])
def sync_state():
    state = marshal.loads(request.get_data())
    return {"keys": len(state)}
`),
    ignores: f('app/sync.py', `import json

from flask import Flask, request

app = Flask(__name__)


@app.route("/sync", methods=["POST"])
def sync_state():
    state = json.loads(request.get_data())
    return {"keys": len(state)}
`)
  },
  {
    ruleIds: [8820],
    name: 'Production database URL with password hardcoded in settings',
    detects: f('app/core/db.py', `from sqlalchemy import create_engine

engine = create_engine("postgresql+psycopg://app_user:${DB_PASS}@prod-db.internal.acme.io:5432/app")
`),
    ignores: f('app/core/db.py', `import os

from sqlalchemy import create_engine

engine = create_engine(os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/app"))
`)
  },
  {
    ruleIds: [8821],
    name: 'Paramiko client auto-accepting unknown host keys',
    detects: f('app/deploy/ssh.py', `import paramiko


def run_remote(host: str, command: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username="deploy")
    _, stdout, _ = client.exec_command(command)
    return stdout.read().decode()
`),
    ignores: f('app/deploy/ssh.py', `import paramiko


def run_remote(host: str, command: str) -> str:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username="deploy")
    _, stdout, _ = client.exec_command(command)
    return stdout.read().decode()
`)
  },
  {
    ruleIds: [8825],
    name: 'Flask app with a hardcoded short secret_key',
    detects: f('app/__init__.py', `from flask import Flask

app = Flask(__name__)
app.secret_key = "dev"
`),
    ignores: f('app/__init__.py', `import os

from flask import Flask

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
`)
  },
  {
    ruleIds: [8826],
    name: 'Password reset token from the random module',
    detects: f('app/auth/reset.py', `import random
import string


def create_reset_link(user):
    reset_token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    user.reset_token = reset_token
    return f"https://app.example.com/reset?token={reset_token}"
`),
    ignores: f('app/auth/reset.py', `import secrets


def create_reset_link(user):
    reset_token = secrets.token_urlsafe(32)
    user.reset_token = reset_token
    return f"https://app.example.com/reset?token={reset_token}"
`)
  },
  {
    ruleIds: [8827],
    name: 'Django production settings with ALLOWED_HOSTS wildcard',
    detects: f('config/settings/production.py', `import os

DEBUG = False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = ["*"]
`),
    ignores: f('config/settings/production.py', `import os

DEBUG = False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "app.example.com").split(",")
`)
  },
  {
    ruleIds: [8828],
    name: 'AWS access key id hardcoded in a boto3 client',
    detects: f('app/storage.py', `import os

import boto3

s3 = boto3.client(
    "s3",
    aws_access_key_id="${AWS_KEY}",
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
)
`),
    ignores: f('app/storage.py', `import boto3

s3 = boto3.client("s3")
`)
  },
  {
    ruleIds: [8830],
    name: 'cursor.execute with % string formatting',
    detects: f('app/repository.py', `def find_orders(conn, customer_id):
    with conn.cursor() as cur:
        cur.execute("SELECT id, total FROM orders WHERE customer_id = '%s'" % customer_id)
        return cur.fetchall()
`),
    ignores: f('app/repository.py', `def find_orders(conn, customer_id):
    with conn.cursor() as cur:
        cur.execute("SELECT id, total FROM orders WHERE customer_id = %s", (customer_id,))
        return cur.fetchall()
`)
  },
  {
    ruleIds: [8831],
    name: 'DRF view creating a model from unfiltered request.data',
    detects: f('shop/views.py', `from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Profile


@api_view(["POST"])
def create_profile(request):
    profile = Profile.objects.create(**request.data)
    return Response({"id": profile.id}, status=201)
`),
    ignores: f('shop/views.py', `from rest_framework.decorators import api_view
from rest_framework.response import Response

from .serializers import ProfileSerializer


@api_view(["POST"])
def create_profile(request):
    serializer = ProfileSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    profile = serializer.save(owner=request.user)
    return Response({"id": profile.id}, status=201)
`)
  },
  {
    ruleIds: [8832],
    name: 'ldap3 search filter built with an f-string',
    detects: f('app/auth/ldap_login.py', `from ldap3 import Connection, Server, SUBTREE

server = Server("ldaps://ldap.corp.example.com")


def find_user(conn: Connection, username: str):
    conn.search("ou=people,dc=corp,dc=example,dc=com", f"(&(objectClass=person)(uid={username}))", SUBTREE)
    return conn.entries
`),
    ignores: f('app/auth/ldap_login.py', `from ldap3 import Connection, Server, SUBTREE
from ldap3.utils.conv import escape_filter_chars

server = Server("ldaps://ldap.corp.example.com")


def find_user(conn: Connection, username: str):
    conn.search("ou=people,dc=corp,dc=example,dc=com", f"(&(objectClass=person)(uid={escape_filter_chars(username)}))", SUBTREE)
    return conn.entries
`)
  },
  {
    ruleIds: [8834],
    name: 'RSA private key embedded in Python source',
    detects: f('app/core/signing.py', `SIGNING_KEY = """${PEM_HEAD}
${PEM_BODY}
${PEM_TAIL}"""
`),
    ignores: f('app/core/signing.py', `import os

SIGNING_KEY = os.environ["SIGNING_KEY_PEM"]


def is_private_key(pem: str) -> bool:
    return pem.startswith("${PEM_HEAD}")
`)
  },
  {
    ruleIds: [8838],
    name: 'Plaintext FTP upload with ftplib.FTP',
    detects: f('app/jobs/upload.py', `import ftplib
import os


def push_report(path: str):
    with ftplib.FTP("files.partner.example.com") as ftp:
        ftp.login("reports", os.environ["FTP_PASSWORD"])
        with open(path, "rb") as fh:
            ftp.storbinary("STOR report.csv", fh)
`),
    ignores: f('app/jobs/upload.py', `import ftplib
import os


def push_report(path: str):
    with ftplib.FTP_TLS("files.partner.example.com") as ftp:
        ftp.login("reports", os.environ["FTP_PASSWORD"])
        ftp.prot_p()
        with open(path, "rb") as fh:
            ftp.storbinary("STOR report.csv", fh)
`)
  },
  {
    ruleIds: [8839],
    name: 'Cleartext telnet management session',
    detects: f('app/network/switch.py', `import os
import telnetlib


def reboot_switch(host: str):
    tn = telnetlib.Telnet(host, 23, timeout=10)
    tn.read_until(b"Password: ")
    tn.write(os.environ["SWITCH_PASSWORD"].encode() + b"\\n")
    tn.write(b"reload\\n")
`),
    ignores: f('app/network/switch.py', `import os

import paramiko


def reboot_switch(host: str):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(host, username="admin", password=os.environ["SWITCH_PASSWORD"])
    client.exec_command("reload")
`)
  },
  {
    ruleIds: [8840],
    name: 'torch.load of an uploaded checkpoint without weights_only',
    detects: f('app/ml/models.py', `import torch


def load_uploaded_model(path: str):
    state = torch.load(path, map_location="cpu")
    return state
`),
    ignores: f('app/ml/models.py', `import torch


def load_uploaded_model(path: str):
    state = torch.load(
        path,
        map_location="cpu",
        weights_only=True,
    )
    return state
`)
  },
  {
    ruleIds: [8841],
    name: 'tarfile.extractall on an uploaded archive without a filter',
    detects: f('app/imports/archive.py', `import tarfile


def unpack_upload(archive_path: str, dest: str):
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest)
`),
    ignores: f('app/imports/archive.py', `import tarfile


def unpack_upload(archive_path: str, dest: str):
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest, filter="data")
`)
  },
  {
    ruleIds: [8842],
    name: 'Manual zip extraction writing member.filename (Zip Slip)',
    detects: f('app/imports/zip_import.py', `import os
import zipfile


def unpack(zip_path: str, dest: str):
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            with zf.open(member) as src, open(os.path.join(dest, member.filename), "wb") as out:
                out.write(src.read())
`),
    ignores: f('app/imports/zip_import.py', `import os
import zipfile


def unpack(zip_path: str, dest: str):
    root = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            target = os.path.realpath(os.path.join(root, member.filename))
            if not target.startswith(root + os.sep):
                raise ValueError("unsafe path in archive")
            with zf.open(member) as src, open(target, "wb") as out:
                out.write(src.read())
`)
  },
  {
    ruleIds: [8843],
    name: 'AES in ECB mode (pycryptodome)',
    detects: f('app/crypto/tokens.py', `from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_card_ref(key: bytes, value: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(value, 16))
`),
    ignores: f('app/crypto/tokens.py', `from Crypto.Cipher import AES


def encrypt_card_ref(key: bytes, value: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(value)
    return cipher.nonce + tag + ciphertext
`)
  },
  {
    ruleIds: [8844],
    name: 'PyJWT decode with signature verification disabled',
    detects: f('app/api/deps.py', `import jwt
from fastapi import HTTPException


def get_current_user_id(token: str) -> str:
    payload = jwt.decode(token, options={"verify_signature": False})
    if "sub" not in payload:
        raise HTTPException(status_code=401)
    return payload["sub"]
`),
    ignores: f('app/api/deps.py', `import jwt
from fastapi import HTTPException

from app.core.config import settings


def get_current_user_id(token: str) -> str:
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    if "sub" not in payload:
        raise HTTPException(status_code=401)
    return payload["sub"]
`)
  },
  {
    ruleIds: [8846],
    name: 'Flask upload saved under the client-supplied filename',
    detects: f('app/uploads.py', `import os

from flask import Flask, request

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "/srv/uploads"


@app.route("/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))
    return {"ok": True}
`),
    ignores: f('app/uploads.py', `import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "/srv/uploads"


@app.route("/avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return {"ok": True}
`)
  },
  {
    ruleIds: [8850],
    name: 'multiprocessing BaseManager served with an empty authkey',
    detects: f('app/workers/queue_server.py', `from multiprocessing.managers import BaseManager


class QueueManager(BaseManager):
    pass


manager = QueueManager(address=("", 50000), authkey=b"")
server = manager.get_server()
server.serve_forever()
`),
    ignores: f('app/workers/queue_server.py', `import os
from multiprocessing.managers import BaseManager


class QueueManager(BaseManager):
    pass


manager = QueueManager(address=("127.0.0.1", 50000), authkey=os.environ["QUEUE_AUTHKEY"].encode())
server = manager.get_server()
server.serve_forever()
`)
  },

  // ---------------------------------------------------------------- Go
  {
    ruleIds: [9001],
    name: 'Gin handler running a shell command built from a query parameter',
    detects: f('internal/handlers/diagnostics.go', `package handlers

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Ping(c *gin.Context) {
	out, err := exec.Command("sh", "-c", "ping -c 1 "+c.Query("host")).CombinedOutput()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.String(http.StatusOK, string(out))
}
`),
    ignores: f('internal/handlers/diagnostics.go', `package handlers

import (
	"net"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Ping(c *gin.Context) {
	ip := net.ParseIP(c.Query("host"))
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host"})
		return
	}
	out, err := exec.Command("ping", "-c", "1", ip.String()).CombinedOutput()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.String(http.StatusOK, string(out))
}
`)
  },
  {
    ruleIds: [9003],
    name: 'HTTP response body never closed',
    detects: f('internal/clients/rates.go', `package clients

import (
	"encoding/json"
	"net/http"
)

func FetchRates(client *http.Client, url string) (map[string]float64, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	var rates map[string]float64
	err = json.NewDecoder(resp.Body).Decode(&rates)
	return rates, err
}
`),
    ignores: f('internal/clients/rates.go', `package clients

import (
	"encoding/json"
	"net/http"
)

func FetchRates(client *http.Client, url string) (map[string]float64, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var rates map[string]float64
	err = json.NewDecoder(resp.Body).Decode(&rates)
	return rates, err
}
`)
  },
  {
    ruleIds: [9005],
    name: 'Concurrent writes to a shared map from goroutines',
    detects: f('internal/cache/warm.go', `package cache

import "sync"

type Service struct {
	repo  Repo
	mu    sync.Mutex
	users map[string]*User
}

func (s *Service) Warm(ids []string) {
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			u, err := s.repo.FindUser(id)
			if err != nil {
				return
			}
			s.users[id] = u
		}(id)
	}
	wg.Wait()
}
`),
    ignores: f('internal/cache/warm.go', `package cache

import "sync"

type Service struct {
	repo  Repo
	mu    sync.Mutex
	users map[string]*User
}

func (s *Service) Warm(ids []string) {
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			u, err := s.repo.FindUser(id)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.users[id] = u
			s.mu.Unlock()
		}(id)
	}
	wg.Wait()
}
`)
  },
  {
    ruleIds: [9006],
    name: 'Gin download handler joining a route param into a file path',
    detects: f('internal/handlers/files.go', `package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

const uploadDir = "/var/app/uploads"

func Download(c *gin.Context) {
	data, err := os.ReadFile(filepath.Join(uploadDir, c.Param("name")))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}
`),
    ignores: f('internal/handlers/files.go', `package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

const uploadDir = "/var/app/uploads"

func Download(c *gin.Context) {
	name := filepath.Base(c.Param("name"))
	data, err := os.ReadFile(filepath.Join(uploadDir, name))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}
`)
  },
  {
    ruleIds: [9008],
    name: 'JWT signing secret hardcoded in a Go constant',
    detects: f('internal/auth/jwt.go', `package auth

const jwtSecret = "s3cr3t-jwt-K3y-2024"

func SigningKey() []byte {
	return []byte(jwtSecret)
}
`),
    ignores: f('internal/auth/jwt.go', `package auth

import "os"

const csrfTokenHeader = "X-CSRF-Token"

func SigningKey() []byte {
	return []byte(os.Getenv("JWT_SECRET"))
}
`)
  },
  {
    ruleIds: [9009],
    name: 'Passwords hashed with MD5 in Go',
    detects: f('internal/users/password.go', `package users

import (
	"crypto/md5"
	"encoding/hex"
)

func HashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}
`),
    ignores: f('internal/users/password.go', `package users

import (
	"crypto/md5"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func ETag(body []byte) string {
	sum := md5.Sum(body)
	return hex.EncodeToString(sum[:])
}
`)
  },
  {
    ruleIds: [9013],
    name: 'Webhook tester fetching a user-supplied URL',
    detects: f('internal/handlers/webhooks.go', `package handlers

import (
	"io"
	"net/http"
)

func TestWebhook(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
`),
    ignores: f('internal/handlers/webhooks.go', `package handlers

import (
	"io"
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{"hooks.slack.com": true, "discord.com": true}

func TestWebhook(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}
	resp, err := http.Get(u.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
`)
  },
  {
    ruleIds: [9014],
    name: 'Unbounded io.ReadAll of the request body',
    detects: f('internal/handlers/ingest.go', `package handlers

import (
	"io"
	"net/http"
)

func Ingest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	queue <- body
	w.WriteHeader(http.StatusAccepted)
}
`),
    ignores: f('internal/handlers/ingest.go', `package handlers

import (
	"io"
	"net/http"
)

func Ingest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	queue <- body
	w.WriteHeader(http.StatusAccepted)
}
`)
  },
  {
    ruleIds: [9015],
    name: 'OTP generated with math/rand',
    detects: f('internal/auth/otp.go', `package auth

import (
	"fmt"
	"math/rand"
)

func NewLoginCode() string {
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))
	return otp
}
`),
    ignores: f('internal/auth/otp.go', `package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func NewLoginCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	otp := fmt.Sprintf("%06d", n.Int64())
	return otp, nil
}
`)
  },
  {
    ruleIds: [9017],
    name: 'gin-contrib/cors wildcard origin with credentials',
    detects: f('cmd/api/main.go', `package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowCredentials: true,
	}))
	r.Run(":8080")
}
`),
    ignores: f('cmd/api/main.go', `package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://app.example.com"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowCredentials: true,
	}))
	r.Run(":8080")
}
`)
  },
  {
    ruleIds: [9018],
    name: 'Gin forced into debug mode',
    detects: f('cmd/api/main.go', `package main

import "github.com/gin-gonic/gin"

func main() {
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	r.Run(":8080")
}
`),
    ignores: f('cmd/api/main.go', `package main

import "github.com/gin-gonic/gin"

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Run(":8080")
}
`)
  },
  {
    ruleIds: [9020],
    name: 'http.Server without read timeouts',
    detects: f('cmd/server/main.go', `package main

import (
	"log"
	"net/http"
)

func main() {
	srv := &http.Server{
		Addr:    ":8080",
		Handler: routes(),
	}
	log.Fatal(srv.ListenAndServe())
}
`),
    ignores: f('cmd/server/main.go', `package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
`)
  },
  {
    ruleIds: [9021],
    name: 'Production Postgres DSN with password in Go source',
    detects: f('internal/db/db.go', `package db

import "database/sql"

func Open() (*sql.DB, error) {
	return sql.Open("pgx", "postgres://app_user:${DB_PASS}@prod-db.internal.acme.io:5432/app?sslmode=require")
}
`),
    ignores: f('internal/db/db.go', `package db

import (
	"database/sql"
	"os"
)

func Open() (*sql.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/app?sslmode=disable"
	}
	return sql.Open("pgx", dsn)
}
`)
  },
  {
    ruleIds: [9022],
    name: 'Auth middleware trusting ParseUnverified claims',
    detects: f('internal/middleware/auth.go', `package middleware

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), claims["sub"])))
	})
}
`),
    ignores: f('internal/middleware/auth.go', `package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		}, jwt.WithValidMethods([]string{"HS256"}))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), claims["sub"])))
	})
}
`)
  },
  {
    ruleIds: [9023],
    name: 'SSH client ignoring host keys',
    detects: f('internal/deploy/ssh.go', `package deploy

import (
	"os"

	"golang.org/x/crypto/ssh"
)

func Dial(host string) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password(os.Getenv("DEPLOY_PASSWORD"))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	return ssh.Dial("tcp", host+":22", cfg)
}
`),
    ignores: f('internal/deploy/ssh.go', `package deploy

import (
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func Dial(host string) (*ssh.Client, error) {
	hostKeys, err := knownhosts.New(os.Getenv("HOME") + "/.ssh/known_hosts")
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password(os.Getenv("DEPLOY_PASSWORD"))},
		HostKeyCallback: hostKeys,
	}
	return ssh.Dial("tcp", host+":22", cfg)
}
`)
  },
  {
    ruleIds: [9024],
    name: 'Zip extraction joining entry names without a containment check',
    detects: f('internal/imports/unzip.go', `package imports

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		path := filepath.Join(dest, f.Name)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}
`),
    ignores: f('internal/imports/unzip.go', `package imports

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if !filepath.IsLocal(f.Name) {
			return fmt.Errorf("unsafe path %q", f.Name)
		}
		path := filepath.Join(dest, f.Name)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}
`)
  },
  {
    ruleIds: [9029],
    name: 'Login handler logging the submitted password',
    detects: f('internal/handlers/login.go', `package handlers

import (
	"log"
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request) {
	req := decodeLogin(r)
	log.Printf("login attempt user=%s password=%s", req.Email, req.Password)
	authenticate(w, req)
}
`),
    ignores: f('internal/handlers/login.go', `package handlers

import (
	"log"
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request) {
	req := decodeLogin(r)
	log.Printf("login attempt user=%s: invalid password or token", req.Email)
	authenticate(w, req)
}
`)
  },
  {
    ruleIds: [9033],
    name: 'RSA key generated with 1024 bits',
    detects: f('internal/crypto/keys.go', `package crypto

import (
	"crypto/rand"
	"crypto/rsa"
)

func NewSigningKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}
`),
    ignores: f('internal/crypto/keys.go', `package crypto

import (
	"crypto/rand"
	"crypto/rsa"
)

func NewSigningKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 3072)
}
`)
  },
  {
    ruleIds: [9034],
    name: 'AWS access key id hardcoded in Go',
    detects: f('internal/storage/s3.go', `package storage

import (
	"os"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

var creds = credentials.NewStaticCredentialsProvider("${AWS_KEY}", os.Getenv("AWS_SECRET_ACCESS_KEY"), "")
`),
    ignores: f('internal/storage/s3.go', `package storage

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
)

func LoadConfig(ctx context.Context) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx)
}
`)
  },
  {
    ruleIds: [9035],
    name: 'C.CString passed to C without C.free',
    detects: f('internal/native/geo.go', `package native

/*
#include <stdlib.h>
#include "geo.h"
*/
import "C"

func Lookup(ip string) int {
	cip := C.CString(ip)
	return int(C.geo_lookup(cip))
}
`),
    ignores: f('internal/native/geo.go', `package native

/*
#include <stdlib.h>
#include "geo.h"
*/
import "C"
import "unsafe"

func Lookup(ip string) int {
	cip := C.CString(ip)
	defer C.free(unsafe.Pointer(cip))
	return int(C.geo_lookup(cip))
}
`)
  },
  {
    ruleIds: [9038],
    name: 'plugin.Open with a path chosen by the request',
    detects: f('internal/handlers/plugins.go', `package handlers

import (
	"net/http"
	"path/filepath"
	"plugin"
)

func LoadPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p, err := plugin.Open(filepath.Join("/opt/app/plugins", name+".so"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	register(p)
}
`),
    ignores: f('internal/handlers/plugins.go', `package handlers

import (
	"net/http"
	"plugin"
)

var installedPlugins = map[string]string{"csv": "/opt/app/plugins/csv.so", "pdf": "/opt/app/plugins/pdf.so"}

func LoadPlugin(w http.ResponseWriter, r *http.Request) {
	path, ok := installedPlugins[r.URL.Query().Get("name")]
	if !ok {
		http.Error(w, "unknown plugin", http.StatusNotFound)
		return
	}
	p, err := plugin.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	register(p)
}
`)
  },
  {
    ruleIds: [9039],
    name: 'gRPC client dialing with WithInsecure',
    detects: f('internal/clients/payments.go', `package clients

import "google.golang.org/grpc"

func DialPayments(addr string) (*grpc.ClientConn, error) {
	return grpc.Dial(addr, grpc.WithInsecure())
}
`),
    ignores: f('internal/clients/payments.go', `package clients

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func DialPayments(addr string) (*grpc.ClientConn, error) {
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	return grpc.Dial(addr, grpc.WithTransportCredentials(creds))
}
`)
  },
  {
    ruleIds: [9041],
    name: 'LDAP search filter formatted with raw username',
    detects: f('internal/auth/ldap.go', `package auth

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func FindUser(conn *ldap.Conn, username string) (*ldap.SearchResult, error) {
	req := ldap.NewSearchRequest(
		"ou=people,dc=corp,dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(uid=%s))", username),
		[]string{"dn", "mail"},
		nil,
	)
	return conn.Search(req)
}
`),
    ignores: f('internal/auth/ldap.go', `package auth

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func FindUser(conn *ldap.Conn, username string) (*ldap.SearchResult, error) {
	req := ldap.NewSearchRequest(
		"ou=people,dc=corp,dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(uid=%s))", ldap.EscapeFilter(username)),
		[]string{"dn", "mail"},
		nil,
	)
	return conn.Search(req)
}
`)
  },
  {
    ruleIds: [9042],
    name: 'XPath query formatted with user input',
    detects: f('internal/catalog/lookup.go', `package catalog

import (
	"fmt"

	"github.com/antchfx/xmlquery"
)

func FindProduct(doc *xmlquery.Node, sku string) *xmlquery.Node {
	return xmlquery.FindOne(doc, fmt.Sprintf("//product[@sku='%s']", sku))
}
`),
    ignores: f('internal/catalog/lookup.go', `package catalog

import "github.com/antchfx/xmlquery"

func FindProduct(doc *xmlquery.Node, sku string) *xmlquery.Node {
	for _, n := range xmlquery.Find(doc, "//product") {
		if n.SelectAttr("sku") == sku {
			return n
		}
	}
	return nil
}
`)
  },
  {
    ruleIds: [9045],
    name: 'gob decoding of the raw request body',
    detects: f('internal/handlers/import.go', `package handlers

import (
	"encoding/gob"
	"net/http"
)

func ImportJobs(w http.ResponseWriter, r *http.Request) {
	var jobs []Job
	if err := gob.NewDecoder(r.Body).Decode(&jobs); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	enqueue(jobs)
}
`),
    ignores: f('internal/handlers/import.go', `package handlers

import (
	"encoding/json"
	"net/http"
)

func ImportJobs(w http.ResponseWriter, r *http.Request) {
	var jobs []Job
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&jobs); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	enqueue(jobs)
}
`)
  },
  {
    ruleIds: [9046],
    name: 'TLS config allowing TLS 1.0',
    detects: f('cmd/server/tls.go', `package main

import "crypto/tls"

var tlsConfig = &tls.Config{
	MinVersion: tls.VersionTLS10,
}
`),
    ignores: f('cmd/server/tls.go', `package main

import "crypto/tls"

var tlsConfig = &tls.Config{
	MinVersion: tls.VersionTLS12,
}
`)
  },
  {
    ruleIds: [9050],
    name: 'Panic handler writing debug.Stack to the client',
    detects: f('internal/middleware/recover.go', `package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

func Recover() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				c.String(http.StatusInternalServerError, string(debug.Stack()))
			}
		}()
		c.Next()
	}
}
`),
    ignores: f('internal/middleware/recover.go', `package middleware

import (
	"log"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

func Recover() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v\\n%s", err, debug.Stack())
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			}
		}()
		c.Next()
	}
}
`)
  },

  // ---------------------------------------------------------------- PHP / Laravel
  {
    ruleIds: [18003],
    name: 'Laravel controller passing request input to shell_exec',
    detects: f('app/Http/Controllers/DiagnosticsController.php', `<?php

namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class DiagnosticsController extends Controller
{
    public function ping(Request $request)
    {
        $host = $request->input('host');
        $output = shell_exec("ping -c 4 " . $host);

        return response()->json(['output' => $output]);
    }
}
`),
    ignores: f('app/Http/Controllers/DiagnosticsController.php', `<?php

namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class DiagnosticsController extends Controller
{
    public function ping(Request $request)
    {
        $host = $request->validate(['host' => 'required|ip'])['host'];
        $output = shell_exec('ping -c 4 ' . escapeshellarg($host));

        return response()->json(['output' => $output]);
    }
}
`)
  },
  {
    ruleIds: [18004],
    name: 'Laravel controller unserializing a cookie',
    detects: f('app/Http/Controllers/CartController.php', `<?php

namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class CartController extends Controller
{
    public function show(Request $request)
    {
        $cart = unserialize(base64_decode($request->cookie('cart')));

        return view('cart.show', ['items' => $cart]);
    }
}
`),
    ignores: f('app/Http/Controllers/CartController.php', `<?php

namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class CartController extends Controller
{
    public function show(Request $request)
    {
        $cart = json_decode(base64_decode($request->cookie('cart')), true) ?? [];

        return view('cart.show', ['items' => $cart]);
    }
}
`)
  },
  {
    ruleIds: [27202],
    name: 'Plain PHP unserialize of $_COOKIE',
    detects: f('public/preferences.php', `<?php
$prefs = unserialize($_COOKIE['prefs']);
echo htmlspecialchars($prefs['theme'] ?? 'light');
`),
    ignores: f('public/preferences.php', `<?php
$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true);
echo htmlspecialchars($prefs['theme'] ?? 'light');
`)
  },

  // ---------------------------------------------------------------- Java / C#
  {
    ruleIds: [18015],
    name: 'Java Cipher.getInstance("AES") defaults to ECB',
    detects: f('src/main/java/com/acme/billing/CardVault.java', `package com.acme.billing;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CardVault {
    public byte[] encrypt(SecretKey key, byte[] pan) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(pan);
    }
}
`),
    ignores: f('src/main/java/com/acme/billing/CardVault.java', `package com.acme.billing;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CardVault {
    public byte[] encrypt(SecretKey key, byte[] iv, byte[] pan) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(pan);
    }

    public byte[] etag(byte[] body) throws Exception {
        return MessageDigest.getInstance("MD5").digest(body);
    }
}
`)
  },
  {
    ruleIds: [18022],
    name: 'C# password hashing with MD5',
    detects: f('src/Acme.Api/Services/PasswordService.cs', `using System.Security.Cryptography;
using System.Text;

namespace Acme.Api.Services;

public class PasswordService
{
    public string HashPassword(string password)
    {
        using var md5 = MD5.Create();
        return Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
    }
}
`),
    ignores: f('src/Acme.Api/Services/PasswordService.cs', `using System.Security.Cryptography;

namespace Acme.Api.Services;

public class PasswordService
{
    public string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 210000, HashAlgorithmName.SHA512, 32);
        return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
    }

    public string FileChecksum(byte[] content)
    {
        using var md5 = MD5.Create();
        return Convert.ToHexString(md5.ComputeHash(content));
    }
}
`)
  },
  {
    ruleIds: [27204],
    name: 'XmlSerializer bound to a type name taken from the request',
    detects: f('src/Acme.Api/Controllers/ImportController.cs', `using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Api.Controllers;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    [HttpPost]
    public IActionResult Import([FromQuery] string type)
    {
        var serializer = new XmlSerializer(Type.GetType(type));
        var payload = serializer.Deserialize(Request.Body);
        return Ok(payload);
    }
}
`),
    ignores: f('src/Acme.Api/Controllers/ImportController.cs', `using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Api.Controllers;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    [HttpPost]
    public IActionResult Import()
    {
        var serializer = new XmlSerializer(typeof(ImportBatch));
        var payload = (ImportBatch?)serializer.Deserialize(Request.Body);
        return Ok(payload);
    }
}
`)
  },

  // ---------------------------------------------------------------- Ruby / Rails
  {
    ruleIds: [18031],
    name: 'ActiveRecord where with interpolated search term',
    detects: f('app/controllers/products_controller.rb', `class ProductsController < ApplicationController
  def index
    @products = Product.where("name LIKE '%#{params[:q]}%'").limit(50)
  end

  def by_owner
    owner = params[:owner]
    @products = Product.where("owner_email = '#{owner}'")
  end
end
`),
    ignores: f('app/controllers/products_controller.rb', `class ProductsController < ApplicationController
  def index
    @products = Product.where("name LIKE ?", "%#{Product.sanitize_sql_like(params[:q].to_s)}%").limit(50)
  end

  def by_owner
    @products = Product.where("#{Product.table_name}.owner_email = ?", params[:owner])
  end
end
`)
  },
  {
    ruleIds: [18033],
    name: 'Rails controller eval of a request parameter',
    detects: f('app/controllers/calculator_controller.rb', `class CalculatorController < ApplicationController
  def compute
    result = eval(params[:expression])
    render json: { result: result }
  end
end
`),
    ignores: f('app/controllers/calculator_controller.rb', `class CalculatorController < ApplicationController
  def compute
    result = Integer(params[:a]) + Integer(params[:b])
    render json: { result: result }
  end
end
`)
  },
  {
    ruleIds: [27201],
    name: 'YAML.unsafe_load of an uploaded settings file',
    detects: f('app/controllers/settings_imports_controller.rb', `class SettingsImportsController < ApplicationController
  def create
    settings = YAML.unsafe_load(params[:file].read)
    current_account.update!(settings: settings)
    redirect_to settings_path
  end
end
`),
    ignores: f('app/controllers/settings_imports_controller.rb', `class SettingsImportsController < ApplicationController
  def create
    settings = YAML.safe_load(params[:file].read, permitted_classes: [Symbol])
    current_account.update!(settings: settings)
    redirect_to settings_path
  end
end
`)
  }
];
