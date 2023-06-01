#!/usr/bin/env python3
'''Module for AnalyticsReport model'''
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class AnalyticsReport(Base):
    '''Class to interact with AnalyticsReport table'''
    __tablename__ = 'analytics_reports'

    id = Column(Integer, primary_key=True)
    clicks = Column(Integer)
    impressions = Column(Integer)
    conversions = Column(Integer)
    title = Column(String(100), nullable=False)
    description = Column(String(500))
    generated_at = Column(DateTime)

    campaign_id = Column(Integer, ForeignKey('campaign.id'))
