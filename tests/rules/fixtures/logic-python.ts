import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29704], name: 'BUG-94 field default evaluated at import',
    detects: f('app/models.py', `from django.db import models
from django.utils import timezone


class Order(models.Model):
    placed_at = models.DateTimeField(default=timezone.now())
`),
    ignores: f('app/models.py', `from django.db import models
from django.utils import timezone
import uuid


class Order(models.Model):
    placed_at = models.DateTimeField(default=timezone.now)
    ref = models.UUIDField(default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)
`),
  },
  {
    ruleIds: [29705], name: 'BUG-95 created_at with auto_now',
    detects: f('app/models.py', `from django.db import models


class Post(models.Model):
    created_at = models.DateTimeField(auto_now=True)
`),
    ignores: f('app/models.py', `from django.db import models


class Post(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
`),
  },
  {
    ruleIds: [29706], name: 'BUG-96 env flag read as string',
    detects: f('config/settings.py', `import os

DEBUG = os.environ.get("DEBUG", False)
SEND_EMAILS = bool(os.getenv("SEND_EMAILS"))
`),
    ignores: f('config/settings.py', `import os

DEBUG = os.environ.get("DEBUG", "false").lower() in ("1", "true", "yes")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")
if os.getenv("SENTRY_DSN"):
    init_sentry()
`),
  },
  {
    ruleIds: [29707], name: 'BUG-97 int(price * 100) truncation',
    detects: f('app/payments.py', `import stripe


def create_intent(order):
    return stripe.PaymentIntent.create(amount=int(order.total * 100), currency="usd")
`),
    ignores: f('app/payments.py', `import stripe


def create_intent(order):
    return stripe.PaymentIntent.create(amount=int(round(order.total * 100)), currency="usd")


def percent(done, total):
    return int(done / total * 100)
`),
  },
  {
    ruleIds: [29708], name: 'BUG-98 result of list.sort() assigned',
    detects: f('app/services/leaderboard.py', `def top_players(players):
    ranked = players.sort(key=lambda p: p.score, reverse=True)
    return ranked[:10]
`),
    ignores: f('app/services/leaderboard.py', `def top_players(players, db):
    ranked = sorted(players, key=lambda p: p.score, reverse=True)
    cursor = db.scores.find().sort("score", -1)
    players.sort(key=lambda p: p.name)
    return ranked[:10], cursor
`),
  },
  {
    ruleIds: [29709], name: 'BUG-99 Celery task inside transaction.atomic',
    detects: f('orders/views.py', `from django.db import transaction
from .tasks import send_receipt


def checkout(request):
    with transaction.atomic():
        order = Order.objects.create(user=request.user)
        send_receipt.delay(order.id)
    return redirect("done")
`),
    ignores: f('orders/views.py', `from django.db import transaction
from .tasks import send_receipt


def checkout(request):
    with transaction.atomic():
        order = Order.objects.create(user=request.user)
        transaction.on_commit(lambda: send_receipt.delay(order.id))
    send_receipt.delay(order.id)
    return redirect("done")
`),
  },
  {
    ruleIds: [29710], name: 'BUG-100 FastAPI get_db returns instead of yield',
    detects: f('app/main.py', `from fastapi import FastAPI, Depends
from .database import SessionLocal

app = FastAPI()


def get_db():
    db = SessionLocal()
    return db


@app.get("/items")
def items(db=Depends(get_db)):
    return db.query(Item).all()
`),
    ignores: f('app/main.py', `from fastapi import FastAPI, Depends
from .database import SessionLocal

app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/items")
def items(db=Depends(get_db)):
    return db.query(Item).all()
`),
  },
  {
    ruleIds: [29711], name: 'BUG-101 error returned with 200',
    detects: f('app/routes.py', `from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/users/<int:uid>")
def get_user(uid):
    user = User.query.get(uid)
    if user is None:
        return jsonify({"error": "User not found"})
    return jsonify(user.to_dict())
`),
    ignores: f('app/routes.py', `from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/users/<int:uid>")
def get_user(uid):
    user = User.query.get(uid)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    if not user.active:
        return jsonify(
            {"error": "inactive"},
        ), 403
    return jsonify(user.to_dict())
`),
  },
  {
    ruleIds: [29711], name: 'BUG-101 FastAPI dict error with 200',
    detects: f('app/api.py', `from fastapi import APIRouter

router = APIRouter()


@router.get("/orders/{order_id}")
async def get_order(order_id: int):
    order = await Order.get_or_none(id=order_id)
    if not order:
        return {"error": "Order not found"}
    return order
`),
    ignores: f('app/api.py', `from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/orders/{order_id}")
async def get_order(order_id: int):
    order = await Order.get_or_none(id=order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order
`),
  },
  {
    ruleIds: [29712], name: 'BUG-102 missing f prefix',
    detects: f('app/notify.py', `import logging

logger = logging.getLogger(__name__)


def welcome(user):
    name = user.first_name
    logger.info("Sending welcome mail to {name}")
    return "Welcome back, {name}!"
`),
    ignores: f('app/notify.py', `import logging

logger = logging.getLogger(__name__)


def welcome(user):
    name = user.first_name
    logger.info(f"Sending welcome mail to {name}")
    print("Hello {name}".format(name=name))
    return "Use {{name}} in templates"
`),
  },
  {
    ruleIds: [29713], name: 'BUG-103 duplicate route',
    detects: f('app/main.py', `from fastapi import FastAPI

app = FastAPI()


@app.get("/users/me")
def me_v1():
    return {"v": 1}


@app.get("/users/me")
def me():
    return {"v": 2}
`),
    ignores: f('app/main.py', `from fastapi import FastAPI

app = FastAPI()


@app.get("/users/me")
def me():
    return {"v": 2}


@app.post("/users/me")
def update_me():
    return {"ok": True}
`),
  },
  {
    ruleIds: [29714], name: 'BUG-104 naive datetime in Django query',
    detects: f('billing/views.py', `from datetime import datetime
from django.shortcuts import render
from .models import Subscription


def expired(request):
    subs = Subscription.objects.filter(expires_at__lt=datetime.now())
    return render(request, "expired.html", {"subs": subs})
`),
    ignores: f('billing/views.py', `from django.shortcuts import render
from django.utils import timezone
from .models import Subscription


def expired(request):
    subs = Subscription.objects.filter(expires_at__lt=timezone.now())
    return render(request, "expired.html", {"subs": subs})
`),
  },
  {
    ruleIds: [29715], name: 'BUG-105 return inside finally',
    detects: f('app/jobs.py', `def charge(order):
    try:
        gateway.charge(order.total)
    finally:
        order.processed = True
        return True
`),
    ignores: f('app/jobs.py', `def charge(order):
    try:
        gateway.charge(order.total)
    finally:
        order.processed = True
        for line in order.lines:
            if line.done:
                continue
    return True
`),
  },
  {
    ruleIds: [29716], name: 'BUG-106 async session commit without await',
    detects: f('app/crud.py', `from sqlalchemy.ext.asyncio import AsyncSession


async def create_user(db: AsyncSession, data):
    user = User(**data)
    db.add(user)
    db.commit()
    return user
`),
    ignores: f('app/crud.py', `from sqlalchemy.ext.asyncio import AsyncSession


async def create_user(db: AsyncSession, data):
    user = User(**data)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user
`),
  },
];
