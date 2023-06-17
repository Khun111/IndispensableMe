#!/usr/bin/env python3
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template
from dotenv import load_dotenv
from .extensions import db, migrate, bcrypt, mail, jwt
from .key import secret_key
import os

load_dotenv()
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')
database = os.getenv('DB_DATABASE')
user = os.getenv('DB_USERNAME')
password = os.getenv('DB_PASSWORD')
mailpass = os.getenv('MAIL_PASSWORD')


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{database}'
app.config['SECRET_KEY'] = secret_key
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "amure387@gmail.com"
app.config["MAIL_PASSWORD"] = mailpass
app.config["MAIL_DEFAULT_SENDER"] = "amure387@gmail.com"

db.init_app(app)
migrate.init_app(app, db)
mail.init_app(app)
bcrypt.init_app(app)
jwt.init_app(app)

@app.route('/')
@app.route('/home')
@app.route('/index')
def index():
    return render_template('index.html')
from .routes.users import users_bp
app.register_blueprint(users_bp)
if __name__ == '__main__':
    app.run(debug=True)
