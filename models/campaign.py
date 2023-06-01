#!/usr/bin/env python3
'''Module for Campaign model'''
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Float
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


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
    analytics_reports = relationship(
                                     'AnalyticsReport',
                                     backref='campaigns',
                                     cascade='all, delete-orphan')
