import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29002],
    name: 'PYF-02 Django extra() SQL Injection',
    detects: f('views.py', `
def get_items(request):
    sort = request.GET.get('sort')
    return Item.objects.extra(where=[f"name = '{sort}'"])
`),
    ignores: f('views.py', `
def get_items(request):
    sort = request.GET.get('sort')
    return Item.objects.extra(where=["name = %s"], params=[sort])
`)
  },
  {
    ruleIds: [29003],
    name: 'PYF-03 Django mark_safe XSS',
    detects: f('views.py', `
from django.utils.safestring import mark_safe
def render(request):
    name = request.GET.get('name')
    return mark_safe(f"<h1>Hello {name}</h1>")
`),
    ignores: f('views.py', `
from django.utils.html import format_html
def render(request):
    name = request.GET.get('name')
    return format_html("<h1>Hello {}</h1>", name)
`)
  },
  {
    ruleIds: [29014],
    name: 'PYF-14 FastAPI HTMLResponse XSS',
    detects: f('app.py', `
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
app = FastAPI()
@app.get("/")
def read_root(request: Request):
    return HTMLResponse(content=f"<h1>{request.query_params.get('name')}</h1>")
`),
    ignores: f('app.py', `
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import html
app = FastAPI()
@app.get("/")
def read_root(request: Request):
    safe_name = html.escape(request.query_params.get('name', ''))
    return HTMLResponse(content=f"<h1>{safe_name}</h1>")
`)
  },
  {
    ruleIds: [29015],
    name: 'PYF-15 Django HttpResponse XSS',
    detects: f('views.py', `
from django.http import HttpResponse
def index(request):
    return HttpResponse(f"Hello {request.GET.get('name')}")
`),
    ignores: f('views.py', `
from django.http import HttpResponse
from django.utils.html import escape
def index(request):
    return HttpResponse(f"Hello {escape(request.GET.get('name'))}")
`)
  },
  {
    ruleIds: [29016],
    name: 'PYF-16 Flask make_response XSS',
    detects: f('app.py', `
from flask import make_response, request
@app.route('/')
def index():
    return make_response(f"Hello {request.args.get('name')}")
`),
    ignores: f('app.py', `
from flask import make_response, request
import html
@app.route('/')
def index():
    return make_response(f"Hello {html.escape(request.args.get('name', ''))}")
`)
  },
  {
    ruleIds: [29017], name: 'PYF-17 Django CORS allow-all with credentials',
    detects: f('mysite/settings.py', `
INSTALLED_APPS = ["corsheaders"]
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
`),
    ignores: f('mysite/settings.py', `
INSTALLED_APPS = ["corsheaders"]
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
CORS_ALLOW_CREDENTIALS = True
`)
  },
  {
    ruleIds: [29018], name: 'PYF-18 Markup wraps an f-string',
    detects: f('app/views.py', `
from markupsafe import Markup

def greeting(user):
    return Markup(f"<b>Hello {user.name}</b>")
`),
    ignores: f('app/views.py', `
from markupsafe import Markup

def greeting(user):
    return Markup("<b>Hello {}</b>").format(user.name)
`)
  },
];
