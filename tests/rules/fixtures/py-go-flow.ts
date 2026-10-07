import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29501], name: 'FLOW-01 Flask: request value through two assignments into os.system',
    detects: f('app/tools.py', `from flask import request
import os

@app.route('/ping')
def ping():
    host = request.args.get('host')
    cmd = 'ping -c 1 ' + host
    os.system(cmd)
    return 'ok'
`),
    ignores: f('app/tools.py', `from flask import request
import subprocess

@app.route('/ping')
def ping():
    host = request.args.get('host')
    subprocess.run(['ping', '-c', '1', host], check=True)
    port = int(request.args.get('port'))
    os.system('nc -z localhost %d' % port)
    return 'ok'
`),
  },
  {
    ruleIds: [29502], name: 'FLOW-02 FastAPI: query parameter becomes the fetched URL',
    detects: f('app/preview.py', `import requests
from fastapi import APIRouter
router = APIRouter()

@router.get('/preview')
def preview(url: str):
    target = url.strip()
    return requests.get(target, timeout=5).text
`),
    ignores: f('app/preview.py', `import requests
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException
router = APIRouter()
ALLOWED_HOSTS = {'api.github.com'}

@router.get('/preview')
def preview(url: str):
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise HTTPException(400)
    return requests.get(url, timeout=5).text
`),
  },
  {
    ruleIds: [29503], name: 'FLOW-03 Django: GET parameter joined into a path and opened',
    detects: f('reports/views.py', `import os
from django.http import HttpResponse

def download(request):
    name = request.GET.get('file')
    path = os.path.join('/srv/reports', name)
    with open(path) as fh:
        return HttpResponse(fh.read())
`),
    ignores: f('reports/views.py', `import os
from django.http import HttpResponse
from werkzeug.utils import secure_filename

def download(request):
    name = secure_filename(request.GET.get('file'))
    path = os.path.join('/srv/reports', name)
    with open(path) as fh:
        return HttpResponse(fh.read())
`),
  },
  {
    ruleIds: [29504], name: 'FLOW-04 net/http: form value into sh -c',
    detects: f('handlers/ping.go', `package handlers

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	line := "ping -c 1 " + host
	out, _ := exec.Command("sh", "-c", line).Output()
	w.Write(out)
}
`),
    ignores: f('handlers/ping.go', `package handlers

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("ping", "-c", "1", host).Output()
	w.Write(out)
}
`),
  },
  {
    ruleIds: [29505], name: 'FLOW-05 gin: query parameter becomes the fetched URL',
    detects: f('handlers/proxy.go', `package handlers

func Proxy(c *gin.Context) {
	target := c.Query("url")
	resp, err := http.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
`),
    ignores: f('handlers/proxy.go', `package handlers

var allowedHosts = map[string]bool{"api.github.com": true}

func Proxy(c *gin.Context) {
	target := c.Query("url")
	u, err := url.Parse(target)
	if err != nil || !allowedHosts[u.Hostname()] {
		return
	}
	resp, _ := http.Get(u.String())
	defer resp.Body.Close()
}
`),
  },
  {
    ruleIds: [29506], name: 'FLOW-06 chi: URL parameter joined into a path and read',
    detects: f('handlers/files.go', `package handlers

func Download(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p := filepath.Join("/srv/uploads", name)
	data, _ := os.ReadFile(p)
	w.Write(data)
}
`),
    ignores: f('handlers/files.go', `package handlers

func Download(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p := filepath.Clean(filepath.Join("/srv/uploads", name))
	if !strings.HasPrefix(p, "/srv/uploads/") {
		http.Error(w, "bad path", 400)
		return
	}
	data, _ := os.ReadFile(p)
	w.Write(data)
}
`),
  },
];
