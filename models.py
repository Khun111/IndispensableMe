#!/usr/bin/env python3
'''Module to interact with User Model'''
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Float, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from werkzeug.security import generate_password_hash, check_password_hash

Base = declarative_base()


class User(Base):
    '''Class to interact with User table'''
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    campaigns = relationship(
                             'Campaign', back_populates='user', lazy=True,
                             cascade='all, delete-orphan')


class Campaign(Base):
    '''Class to interact with campaign table'''
    __tablename__ = 'campaigns'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    budget = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='campaigns')
    analytics_reports = relationship(
                                     'AnalyticsReport',
                                     back_populates='campaigns',
                                     cascade='all, delete-orphan')


class AnalyticsReport(Base):
    '''Class to interact with AnalyticsReport table'''
    __tablename__ = 'analytics_reports'

    id = Column(Integer, primary_key=True)
    clicks = Column(Integer)
    impressions = Column(Integer)
    conversions = Column(Integer)
    title = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)

    campaigns_id = Column(Integer, ForeignKey('campaigns.id'))
    campaigns = relationship('Campaign', back_populates='analytics_reports')
