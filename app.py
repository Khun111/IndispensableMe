#!/usr/bin/env python3
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from dotenv import load_dotenv
from extensions import db, migrate, bcrypt
from key import secret_key
from routes.users import users_bp, jwt
import os

load_dotenv()
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')
database = os.getenv('DB_DATABASE')
user = os.getenv('DB_USERNAME')
password = os.getenv('DB_PASSWORD')


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{database}'
app.config['SECRET_KEY'] = secret_key

db.init_app(app)
migrate.init_app(app, db)
bcrypt.init_app(app)
jwt.init_app(app)

app.register_blueprint(users_bp)
if __name__ == '__main__':
    app.run()
