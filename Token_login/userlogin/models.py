from django.db import models
from mongoengine import *
# Create your models here.
from djongo  import models



class ConsumerModel(models.Model):  
    
    _id = models.ObjectIdField(primary_key = True)
    first_name = models.CharField(max_length=30,default=None)  
    last_name = models.CharField(max_length=30,default=None)  
    mobile = models.CharField(max_length=10,default=None)  
    email = models.EmailField(default=None)  
    username = models.CharField(max_length=30, default=None )
    password = models.CharField(max_length=30, default=None)
    confirm_password = models.CharField(max_length=30, default=None)
    password_hash = models.CharField(max_length=30, default=None)
  
  
  
  
class DummyRelationModel(models.Model):  
    
    _id = models.ObjectIdField(primary_key = True)
    consumer = models.ForeignKey(ConsumerModel,on_delete=models.CASCADE)
    created = models.DateTimeField()
    firm_name = models.CharField(max_length=30,default=None)
    firm_address = models.CharField(max_length=30,default=None)  
    account_id = models.CharField(max_length=30,default=None)  
    biz_identification_no = models.CharField(max_length=10,default=None)   
    others = models.CharField(max_length=30, default=None )
    