from django.http import JsonResponse
from django.views import View  
from django import forms
from consumer import models
from consumer import forms

from django.conf import settings

from datetime import timedelta, datetime, timezone
from consumerdetails.auth import authenticate, validate_payload
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
import json
import jwt
import os


def create_cofferid():
    uid = os.urandom(8).hex().upper()
    if models.ConsumerModel.objects(coffer_id=uid):
        create_cofferid()
    return uid

def consumer_find(field, value):
    if field in ['email', 'mobile']:
        con = models.ConsumerModel.objects(email=value).first()
        if con:
            con = models.ConsumerModel.objects(email=value.lower()).first()
            return con
    return None




# def consumer_by_cofferid(coffer_id):
#     con = models.ConsumerModel.objects(coffer_id=coffer_id).first()
#     if con:
        
#         return con
#     return None


