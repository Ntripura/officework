from django.db import models

# Create your models here.
from mongoengine import *
from mongoengine import Document, fields
from django.utils import timezone
from datetime import datetime


class CofferAPIUser(Document):
    user = fields.StringField()
    uid = fields.StringField()
    password = fields.StringField()
    created = fields.DateTimeField()

    meta = {'indexes': ['uid'], 'collection': 'coffer_api_user'}

    


class ConsumerModel(Document):  
    coffer_id = fields.StringField(unique = True)
    first_name = fields.StringField(max_length=50)
    last_name = fields.StringField(max_length=50)
    country = fields.StringField(max_length=50)
    gender = fields.StringField(max_length=20)
    mobile = fields.StringField(max_length=20)
    email = fields.EmailField()
    username = fields.StringField(max_length=50)
    password = fields.StringField()
    confirm_password = fields.StringField()
    password_hash = fields.StringField()
    
    meta = {'indexes': ['coffer_id']}


class ConsumerNotifications(Document):  
    consumer = fields.ReferenceField(ConsumerModel)
    message = fields.StringField()
    status = fields.StringField()
    timestamp = fields.DateTimeField()
    priority = fields.IntField()
    
    
class ConsumerReminder(Document):
    consumer = fields.ReferenceField(ConsumerModel)
    target = fields.DateTimeField()
    created = fields.DateTimeField()
    message = fields.StringField()