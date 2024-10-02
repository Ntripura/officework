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
  
  
  
class BusinessModel(models.Model):  
    
    _id = models.ObjectIdField(primary_key = True)
    uid = models.CharField(max_length=30,default=None)  
    name = models.CharField(max_length=30,default=None)  
    category = models.CharField(max_length=10,default=None)  
    subcategory = models.CharField(max_length=10,default=None)  
    country = models.CharField(max_length=10,default=None)  
    contact_person = models.CharField(max_length=30, default=None )
    contact_phone = models.CharField(max_length=30, default=None)
    email = models.EmailField(default=None)  
    password = models.CharField(max_length=30, default=None)
    password_hash = models.CharField(max_length=30, default=None)
    account_status = models.CharField(max_length=10,default=None)  
    joined= models.DateTimeField()
    address = models.CharField(max_length=10,default=None)
    correspondance_address = models.CharField(max_length=10,default=None)
    alias_name = models.CharField(max_length=100,default=None)  
    legal_structure = models.CharField(max_length=100,default=None)  
    company_website = models.CharField(max_length=100,default=None)  
    registration_no = models.CharField(max_length=100,default=None)  #GST No
    aboutus = models.CharField(max_length=1000,default=None)  
    addons =  models.CharField(max_length=1000,default=None)  
    
    
    
class ProfessionalModel(models.Model):  
    
    _id = models.ObjectIdField(primary_key = True)
    uid = models.CharField(max_length=30,default=None)  
    name = models.CharField(max_length=30,default=None)  
    category = models.CharField(max_length=10,default=None)  
    subcategory = models.CharField(max_length=10,default=None)  
    country = models.CharField(max_length=10,default=None)  
    contact_person = models.CharField(max_length=30, default=None )
    contact_phone = models.CharField(max_length=30, default=None)
    email = models.EmailField(default=None)  
    password = models.CharField(max_length=30, default=None)
    password_hash = models.CharField(max_length=30, default=None)
    account_status = models.CharField(max_length=10,default=None)  
    joined= models.DateTimeField()
    address = models.JSONField()
    correspondance_address = models.JSONField()
    alias_name = models.CharField(max_length=100,default=None)  
    legal_structure = models.CharField(max_length=100,default=None)  
    company_website = models.CharField(max_length=100,default=None)  
    registration_no = models.CharField(max_length=100,default=None)  #GST No
    aboutus = models.CharField(max_length=1000,default=None)  
    addons =  models.CharField(max_length=1000,default=None) 
    
  
  
  
class DummyRelationModel(models.Model):  
    
    _id = models.ObjectIdField(primary_key = True)
    consumer = models.ForeignKey(ConsumerModel,on_delete=models.CASCADE)
    created = models.DateTimeField()
    firm_name = models.CharField(max_length=30,default=None)
    firm_address = models.CharField(max_length=30,default=None)  
    account_id = models.CharField(max_length=30,default=None)  
    biz_identification_no = models.CharField(max_length=10,default=None)   
    others = models.CharField(max_length=30, default=None )
    
    
class ReminderModel(models.Model):
    _id = models.ObjectIdField(primary_key = True)
    consumer = models.ForeignKey(ConsumerModel,on_delete=models.CASCADE)
    created = models.DateTimeField()
    target = models.DateTimeField()
    message = models.CharField(max_length=120,default=None)  
     
     
class KYCInformation(models.Model):
    _id = models.ObjectIdField(primary_key = True)
    kyctype = models.CharField(max_length=50,default=None)  
    filename = models.CharField(max_length=50,default=None)  
    content_type = models.CharField(max_length=30,default=None)  
    size = models.CharField(max_length=50,default=None)  
    created = models.DateTimeField()
    verifying_agency = models.CharField(max_length=120,default=None)  
    kyc_status = models.CharField(max_length=120,default=None)  
    kyc_completion_date = models.DateTimeField()
    attestation_frequency = models.IntegerField()
    attestation_date = models.DateTimeField()
    
          
     
    
class RelationshipModel(models.Model):  
    
    _id = models.ObjectIdField(primary_key = True)
    consumer_id = models.ForeignKey(ConsumerModel,on_delete=models.CASCADE)
    biztype = models.CharField(max_length=30,default=None)
    bizuid = models.CharField(max_length=30,default=None)  
    reltype = models.CharField(max_length=30,default=None) 
    created = models.DateTimeField() 
    accepted = models.DateTimeField() 
    isaccepted = models.BooleanField(default=False)
    description= models.CharField(max_length=10,default=None)   
    documents = models.JSONField()
    bizdocuments = models.JSONField()
    profile = models.BooleanField(default=False)
    metadata = models.JSONField()
    global_relationship_id = models.CharField(max_length =30, default=None)
    products = models.JSONField()
    status = models.CharField(max_length=30, default=None)
    tc_consent = models.JSONField()
    email = models.BooleanField()
    mobile = models.BooleanField()
    kyc_info =models.EmbeddedField(model_container=KYCInformation)
    group_acls =  models.JSONField()
    requestor = models.CharField(max_length = 50,default=None)
    biztags =  models.JSONField()
    relationship_type = models.CharField(max_length=30, default=None)
    
    
    
class IdentityDocumentModel(models.Model):  
    
    _id = models.ObjectIdField(primary_key = True)
    consumer_id = models.ForeignKey(ConsumerModel,on_delete=models.CASCADE)
    category = models.CharField(max_length=30,default=None)  
    doctype = models.CharField(max_length=30,default=None)  
    docid = models.CharField(max_length=10,default=None)  
    expiration_date = models.DateTimeField()
    content_type = models.CharField(max_length=30,default=None)  
    filename = models.CharField(max_length=30,default=None)
    created = models.DateTimeField()
    updated = models.DateTimeField()  
    metadata = models.CharField(max_length=10,default=None)  
    docid = models.CharField(max_length=10,default=None)  
    verification_status = models.CharField(max_length=10,default=None)  
    validity_status = models.CharField(max_length=10,default=None)  
    verification_vendor = models.CharField(max_length=10,default=None)  
    ciphertext = models.CharField(max_length=10,default=None)  
    tags = models.CharField(max_length=10,default=None)  
    