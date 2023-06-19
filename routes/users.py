#!/usr/bin/env python3
'''Module for authentication route'''
from datetime import datetime, timedelta
import jwt as pyjwt
from ..key import secret_key
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import request, jsonify, Blueprint, make_response, url_for, session, render_template, redirect, flash
from sqlalchemy.exc import IntegrityError
from ..models import User
from ..extensions import db, jwt, mail, Message
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity, 
    jwt_required,
)

serializer = URLSafeTimedSerializer(secret_key)

users_bp = Blueprint('users', __name__)

def send_email(recipient, message, body):
    msg = Message(message, recipients=[recipient])

    msg.body = body

    mail.send(msg)

@users_bp.route('/dashboard/<name>')
@users_bp.route('/dashboard', defaults={'name': 'User'})
def dashboard(name):
    return render_template('dashboard.html', user=name)
    

@users_bp.route('/campaign')
def campaign():
    return render_template('campaign.html')
    
@users_bp.route('/register', methods=['GET', 'POST'] )
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        try:
            exist = User.query.filter_by(username=username).first()
            if exist:
                flash('User already exist', 'error')
                return redirect(url_for('users.register'))
                #return make_response(jsonify({'message': 'User already exists'}), 409)
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            expiration_time = datetime.utcnow() + timedelta(hours=24)
            payload = {'email': email, 'purpose': 'email_verification','exp': expiration_time.timestamp()}
            token = serializer.dumps(payload)
            verification_link = url_for('users.verify_email', token=token, _external=True)
            body = f'Click here to verify your email: {verification_link}'
            send_email(email, 'Verify Email', body)
            flash('Verification email sent', 'success')
            #return make_response(jsonify({'message': 'Verification email sent'}), 200)
        except IntegrityError as e:
            return make_response(jsonify({'error': 'Error occured during registration'}), 400)
    return render_template('register.html')

@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return make_response(jsonify({"message": "Invalid credentials"}), 401)

@jwt.expired_token_loader
def expired_token_callback(callback):
    return make_response(jsonify({'message': 'Token has expired'}), 401)

@users_bp.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            flash('Invalid username or password', 'error')
            return redirect(url_for('users.login'))
            #return make_response(jsonify({'message': 'Invalid username or password'}), 401) 
        if not user.email_verified:
           # return make_response(jsonify({'message': 'Email not verified. Please verify your email to login.'}), 400)
           flash('Email not verified. Please verify your email to login.', 'error')
           return redirect(url_for('users.login'))

        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return dashboard(username)
    return render_template('login.html')

@users_bp.route('/logout', methods=['GET','POST'])
def logout():
    session.clear()
    #return make_response(jsonify({'message': 'User successfully logged out'}), 200)
    flash('You have successfully logged out', 'success')
    return redirect(url_for('index'))

# @users_bp.route('/secured', methods=['GET'])
# @jwt_required()
# def secured():
#     current_user = get_jwt_identity()
#     return jsonify({'message': 'Secured route', 'user': current_user})

# @users_bp.route('/refresh', methods=['POST'])
# @jwt_required(refresh=True) 
# def refresh():
#     current_user = get_jwt_identity()
#     new_token = create_access_token(identity=current_user)
#     return jsonify({'access_token': new_token})

# def generate_reset_token(user_id):
#     payload = {
#         'user_id': user_id,
#         'purpose': 'email_verification'
#     }
#     reset_token = pyjwt.encode(payload, secret_key, algorithm='HS256')
#     return reset_token

@users_bp.route('/password_request', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if user:
            payload = {'user_id': user.id, 'purpose': 'password_reset'}
            token = serializer.dumps(payload)
            verification_link = url_for('users.reset_password', token=token, _external=True)
            body = f'Click here to reset your password: {verification_link}'
            send_email(user.email, 'Password reset', body)
            flash('An email has been sent to reset your password', 'success')
            return redirect(url_for('users.forgot_password'))
        #return make_response(jsonify({'message': 'An email has been sent to reset your password'}), 200)
    return render_template('forget_Password.html')

@users_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    new_password = request.form.get('new_password')

    if request.method == 'POST':
        try:
            payload = serializer.loads(token)
            user_id = payload['user_id']
            purpose = payload['purpose']

            if purpose == 'password_reset':
                user = User.query.get(user_id)
                user.set_password(new_password)
                db.session.commit()
                flash('Password reset was successful. Login with your new password', 'success')
                return redirect(url_for('users.login'))
        except BadSignature:
            flash('Invalid or expired token', 'success')
            return redirect(url_for('users.forgot_password'))
            #return make_response(jsonify({'message': 'Invalid or expired token'}), 400)
        except Exception as e:
            return make_response(jsonify({'message': 'Error verifying email', 'error': str(e)}), 500)

    return render_template('reset_password.html', token=token)

# @users_bp.route('/email_verification', methods=['POST'])
# def verification_request():
#     email = request.form.get('email')
#     user = User.query.filter_by(email=email).first()

#     if user:
#         verification_token = serializer.dumps({'user_id': user.id, 'purpose': 'email_verification'})
#         verification_link = url_for('users.verify_email', token=verification_token, _external=True)
#         body = f'Click here to reset your password: {verification_link}'
#         send_email(user.email, 'Email verification', body)
#     return make_response(jsonify({'message': 'Email verification sent'}), 200)


@users_bp.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    if not token:
        return make_response(jsonify(error='Invalid Token'), 400)
    try:
        '''Decode and verify the token'''
        payload = serializer.loads(token, max_age=24*3600)
        email = payload['email']
        purpose = payload['purpose']
        expiration_time = payload['exp']
        

        if purpose != 'email_verification':
            return make_response(jsonify({'message': 'Invalid token'}), 400)

        user = User.query.filter_by(email=email).first()
        if not user:
            return make_response(jsonify({'message': 'User not found'}), 400)

        if datetime.utcnow() > datetime.fromtimestamp(expiration_time):
            db.session.delete(user)
            db.session.commit()
            return make_response(jsonify({'message': 'Verification time exceeded and user deleted'}))
        user.email_verified = True
        db.session.commit()

        flash('Email successfully verified', 'success')
        return redirect(url_for('users.login'))
        #return make_response(jsonify({'message': 'Email successfully verified'}), 200)
    except BadSignature:
        flash('Token is invalid or has expired')
        return redirect(url_for('users.register'))
        #return make_response(jsonify({'message': 'Invalid or expired token'}), 400)
    except Exception as e:
        return make_response(jsonify({'message': 'Error verifying email', 'error': str(e)}), 500)

