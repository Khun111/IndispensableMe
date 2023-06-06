#!/usr/bin/env python3
'''Module for authentication route'''
from flask import request, jsonify, Blueprint, make_response
from sqlalchemy.exc import IntegrityError
from models import User
from extensions import db, jwt
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity, 
    jwt_required,
)

users_bp = Blueprint('users', __name__)

@users_bp.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    try:
        exist = User.query.filter_by(username=username).first()
        if exist:
            return make_response(jsonify({'message': 'User already exists'}), 409)
        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        return make_response(jsonify({'message': 'User successfully registered'}), 201)
    except IntegrityError:
        db.session.rollback()
        return make_response(jsonify({'message': 'Error occured during registration'}), 400)
    finally:
        db.session.close()

@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return make_response(jsonify({"message": "Invalid credentials"}), 401)

@jwt.expired_token_loader
def expired_token_callback(callback):
    return make_response(jsonify({'message': 'Token has expired'}), 401)

@users_bp.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return make_response(jsonify({'message': 'Invalid username or password'}), 401) 
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    return make_response(jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200)

@users_bp.route('/secured', methods=['GET'])
@jwt_required()
def secured():
    current_user = get_jwt_identity()
    return jsonify({'message': 'Secured route', 'user': current_user})

@users_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify({'access_token': new_token})
