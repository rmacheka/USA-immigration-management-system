from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models.applicant import Applicant  # We'll create this next

applicants_bp = Blueprint('applicants', __name__, url_prefix='/api/applicants')

@applicants_bp.route('/', methods=['POST'])
def create_applicant():
    data = request.json
    new_applicant = Applicant(
        name=data['name'],
        email=data['email']
    )
    db.session.add(new_applicant)
    db.session.commit()
    return jsonify({"id": new_applicant.id}), 201

@applicants_bp.route('/<int:id>', methods=['GET'])
def get_applicant(id):
    applicant = Applicant.query.get_or_404(id)
    return jsonify({
        "id": applicant.id,
        "name": applicant.name,
        "email": applicant.email
    })