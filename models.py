#!/usr/bin/env python3
'''Module to interact with User Model'''
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Float, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from .extensions import db, bcrypt


class Base(db.Model):
    __abstract__ = True
    id = Column(String(60), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    def __init__(self, *args, **kwargs):
        """Initialization of the base model"""""
        if kwargs:
            for key, value in kwargs.items():
                if key != "__class__":
                    setattr(self, key, value)
            if kwargs.get("created_at", None) and type(self.created_at) is str:
                self.created_at = datetime.strptime(kwargs["created_at"], time)
            else:
                self.created_at = datetime.utcnow()
            if kwargs.get("updated_at", None) and type(self.updated_at) is str:
                self.updated_at = datetime.strptime(kwargs["updated_at"], time)
            else:
                self.updated_at = datetime.utcnow()
            if kwargs.get("id", None) is None:
                self.id = str(uuid.uuid4())
        else:
            self.id = str(uuid.uuid4())
            self.created_at = datetime.utcnow()
            self.updated_at = self.created_at

    def __str__(self):
        """String representation of the BaseModel class"""""
        return "[{:s}] ({:s}) {}".format(self.__class__.__name__, self.id, self.__dict__)

    def save(self):
        """updates the attribute 'updated_at' with the current datetime"""""
        self.updated_at = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def to_dict(self, save_fs=None):
        """returns a dictionary containing all keys/values of the instance"""""
        new_dict = self.__dict__.copy()
        if "created_at" in new_dict:
            new_dict["created_at"] = new_dict["created_at"].strftime(time)
        if "updated_at" in new_dict:
            new_dict["updated_at"] = new_dict["updated_at"].strftime(time)
        new_dict["__class__"] = self.__class__.__name__
        if "_sa_instance_state" in new_dict:
            del new_dict["_sa_instance_state"]
        if save_fs is None:
            if "password" in new_dict:
                del new_dict["password"]
        return new_dict

    def delete(self):
        """delete the current instance from the storage"""""
        db.session.delete(self)

class User(Base):
    '''Class to interact with User table'''
    __tablename__ = 'users'

    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    def __str__(self):
        """String representation of the BaseModel class"""""
        return self.username

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    campaigns = relationship(
                             'Campaign', back_populates='user', lazy=True,
                             cascade='all, delete-orphan')


class Campaign(Base):
    '''Class to interact with campaign table'''
    __tablename__ = 'campaigns'

    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    budget = db.Column(db.Float)

    user_id = db.Column(db.String(60), db.ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='campaigns')
    analytics_reports = relationship(
                                     'AnalyticsReport',
                                     back_populates='campaigns',
                                     cascade='all, delete-orphan')


class AnalyticsReport(Base):
    '''Class to interact with AnalyticsReport table'''
    __tablename__ = 'analytics_reports'

    clicks = db.Column(db.Integer)
    impressions = db.Column(db.Integer)
    conversions = db.Column(db.Integer)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

    campaigns_id = db.Column(db.String(60), db.ForeignKey('campaigns.id'))
    campaigns = relationship('Campaign', back_populates='analytics_reports')
