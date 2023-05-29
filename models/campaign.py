#!/usr/bin/env python3
'''Module for Campaign model'''
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Float
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Campaign(Base):
    '''Class to interact with campaign table'''
    __tablename__ = 'campaigns'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500))
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    budget = Column(Float)

    user_id = Column(Integer, ForeignKey('users.id'))
    analytics_reports = relationship('AnalyticsReport', backref='campaign', cascade='all, delete-orphan')
