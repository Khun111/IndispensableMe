#!/usr/bin/env python3
'''Module to interact with User Model'''
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Float, ForeignKey
from sqlalchemy.orm import relationship
from extensions import db, bcrypt


class User(db.Model):
    '''Class to interact with User table'''
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    campaigns = relationship(
                             'Campaign', back_populates='user', lazy=True,
                             cascade='all, delete-orphan')


class Campaign(db.Model):
    '''Class to interact with campaign table'''
    __tablename__ = 'campaigns'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    budget = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='campaigns')
    analytics_reports = relationship(
                                     'AnalyticsReport',
                                     back_populates='campaigns',
                                     cascade='all, delete-orphan')


class AnalyticsReport(db.Model):
    '''Class to interact with AnalyticsReport table'''
    __tablename__ = 'analytics_reports'

    id = db.Column(db.Integer, primary_key=True)
    clicks = db.Column(db.Integer)
    impressions = db.Column(db.Integer)
    conversions = db.Column(db.Integer)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    campaigns_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    campaigns = relationship('Campaign', back_populates='analytics_reports')
