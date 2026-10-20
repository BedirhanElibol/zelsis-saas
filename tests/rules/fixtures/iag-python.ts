import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile => ({ path, content });

export const CASES: RuleCase[] = [
  {
    ruleIds: [29507], name: 'FLOW-07 FastAPI invoice by URL id for any signed-in user vs owner filter and explicit check',
    detects: [f('app/api/invoices.py', `from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/invoices")
def list_invoices(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Invoice).filter(Invoice.owner_id == current_user.id).all()


@router.get("/invoices/{invoice_id}")
def read_invoice(invoice_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if not invoice:
        raise HTTPException(status_code=404)
    return invoice
`)],
    ignores: [f('app/api/invoices.py', `from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/invoices/{invoice_id}")
def read_invoice(invoice_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id, Invoice.owner_id == current_user.id).first()
    if not invoice:
        raise HTTPException(status_code=404)
    return invoice


@router.delete("/receipts/{receipt_id}")
def delete_receipt(receipt_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    receipt = db.get(Receipt, receipt_id)
    if receipt.user_id != current_user.id:
        raise HTTPException(status_code=403)
    db.delete(receipt)


@router.get("/admin/orders/{order_id}")
def admin_order(order_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_active_superuser)):
    return db.get(Order, order_id)


@router.get("/posts/{post_id}")
def read_post(post_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Post).filter(Post.id == post_id).first()
`)],
  },
  {
    ruleIds: [29507], name: 'FLOW-07 Django view loads a document by pk for any logged-in user vs owner-scoped lookup',
    detects: [f('documents/views.py', `from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render


@login_required
def document_list(request):
    return render(request, "documents/list.html", {"documents": Document.objects.filter(owner=request.user)})


@login_required
def document_detail(request, pk):
    document = get_object_or_404(Document, pk=pk)
    return render(request, "documents/detail.html", {"document": document})
`)],
    ignores: [f('documents/views.py', `from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render


@login_required
def document_detail(request, pk):
    document = get_object_or_404(Document, pk=pk, owner=request.user)
    return render(request, "documents/detail.html", {"document": document})
`)],
  },
  {
    ruleIds: [29507], name: 'FLOW-07 Flask route with Flask-Login reads a note by id vs a route with no sign-in at all',
    detects: [f('app/routes.py', `from flask import Blueprint, jsonify
from flask_login import login_required

bp = Blueprint("notes", __name__)


@bp.route("/notes")
@login_required
def list_notes():
    return jsonify([n.to_dict() for n in Note.query.filter_by(user_id=current_user.id)])


@bp.route("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    note = Note.query.get(note_id)
    return jsonify(note.to_dict())
`)],
    ignores: [f('app/routes.py', `from flask import Blueprint, jsonify

bp = Blueprint("pages", __name__)


@bp.route("/pages/<int:page_id>")
def get_page(page_id):
    page = db.session.get(Page, page_id)
    return jsonify(page.to_dict())
`)],
  },
];
