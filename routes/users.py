#!/usr/bin/env python3
'''Module for authentication route'''
from flask import request, jsonify, Blueprint
from sqlalchemy.exc import IntegrityError
from models import User
from extensions import db
from bcrypt import hashpw, gensalt
users_bp = Blueprint('users', __name__)

@users_bp.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    password_hash = hashpw(password.encode('utf-8'), gensalt())

    try:
        exist = User.query.filter_by(username=username).first()
        if exist:
            return jsonify({'message': 'User already exists'})
        new_user = User(username=username, email=email, password_hash=password_hash)

        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User successfully registered'})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Error occured during registration'})
    finally:
        db.session.close()
