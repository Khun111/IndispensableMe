#!/usr/bin/env python3
import mysql.connector
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

load_dotenv()
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')
database = os.getenv('DB_DATABASE')
user = os.getenv('DB_USERNAME')
password = os.getenv('DB_PASSWORD')

engine = create_engine(f'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{database}')
