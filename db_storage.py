#!/usr/bin/env python3
from sqlalchemy import create_engine
from dotenv import load_dotenv
import os

load_dotenv()
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')
database = os.getenv('DB_DATABASE')
user = os.getenv('DB_USERNAME')

engine = create_engine(f'mysql+mysqlconnector://{user}@{host}:{port}/{database}')
