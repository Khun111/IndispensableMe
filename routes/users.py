#!/usr/bin/env python3
'''Module for authentication route'''
from flask import request, jsonify, Blueprint
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from models.user import User
from models.campaign import Campaign
from db_storage import engine
from flask.ext.login import login_user, login_required, logout_user

Session = sessionmaker(bind=engine)

users_bp = Blueprint('users', __name__)

@users_bp.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    session = Session()
    try:
        exist = session.query(User).filter((User.username == username) | (User.email == email))
        if exist:
            return jsonify({'message': 'User already exists'})
        new_user = User(username=username, email=email)
        new_user.set_password(password)

        session.add(new_user)
        session.commit()
        return jsonify({'message': 'User successfully registered'})
    except IntegrityError:
        session.rollback()
        return jsonify({'message': 'Error occured during registration'})
    finally:
        session.close()
        
        
@users_bp.route('/logout', methods=['POST'])
    def logout():
     logout_user()
    flash('You were logged out.')
    return jsonify({'message': 'User successfully logged out'})
    
    
   
@users_bp.route('/login', methods=['GET', 'POST'])
    def login_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    session = Session()
    try:
        exist = session.query(User).filter((User.username == username) | (User.email == email))
        if exist:
            return jsonify({'message': 'Login in progress'})
        current_user = User(username=username, email=email)
        current_user.verify_password(password)

        session.add(current_user)
        session.commit()
        return jsonify({'message': 'User successfully logged in'})
    except IntegrityError:
        session.rollback()
        return jsonify({'message': 'Error occured during login'})
    finally:
        session.close()

