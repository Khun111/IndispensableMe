#!/usr/bin/env python3
from flask import Flask, request, jsonify, Blueprint
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from models.user import User
from .database import engine

Session = sessionmaker(bind=engine)

users_bp = Blueprint('users', __name__)

@users_bp.route('/register', methods=['POST'])
