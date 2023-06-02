#!/usr/bin/env python3
from sqlalchemy.orm import sessionmaker
from flask import Flask
from routes.users import users_bp
from db_storage import engine

Session = sessionmaker(bind=engine)

app = Flask(__name__)
app.register_blueprint(users_bp)

if __name__ == '__main__':
    app.run()
