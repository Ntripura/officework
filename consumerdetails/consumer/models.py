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

class Event(Document):
    reference = fields.StringField() #uid of prof object
    reference_obj = fields.StringField() #string "professional"
    name = fields.StringField() #
    timestamp = fields.DateTimeField()
    message = fields.StringField()
    level = fields.StringField()    


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


class BusinessModel(Document):
    uid = fields.StringField()
    name = fields.StringField()
    name_hash = fields.StringField()
    category = fields.StringField()
    subcategory = fields.StringField()
    country = fields.StringField()
    contact_person = fields.StringField()
    contact_phone = fields.StringField()
    email = fields.StringField()
    email_hash = fields.StringField()
    email_verified = fields.BooleanField(default=False)
    email_verification_token = fields.StringField()
    password_token = fields.StringField()
    password_token_timestamp = fields.DateTimeField()
    password = fields.StringField()
    password_mode = fields.StringField()
    account_status = fields.StringField(default='pending')
    joined = fields.DateTimeField()
    address = fields.StringField()
    account_info = fields.DictField()
    ciphertext = fields.StringField()
    tcfilename = fields.StringField()
    authtoken = fields.StringField()
    alias_name = fields.StringField()
    correspondance_address = fields.StringField()
    legal_structure = fields.StringField(default = 'None')
    company_website = fields.StringField()
    date_of_incorporation = fields.DateTimeField()
    registration_number = fields.StringField()
    about_us = fields.StringField()
    addons = fields.ListField(default=[])
    
    meta = {'indexes': ['uid']}


class BusinessUser(Document):
    business = fields.ReferenceField(BusinessModel)
    name = fields.StringField()
    email = fields.StringField()
    email_verified = fields.BooleanField()
    password = fields.StringField()
    password_mode = fields.StringField()
    verification_token = fields.StringField()
    account_status = fields.StringField()
    isadmin = fields.BooleanField(default=False)
    group = fields.StringField()
    groups = fields.ListField()
    created = fields.DateTimeField()
    last_login = fields.DateTimeField()



class BusinessNotification(Document):
    business = fields.ReferenceField(BusinessModel)
    user = fields.ReferenceField(BusinessUser)
    message = fields.StringField()
    status = fields.StringField()
    timestamp = fields.DateTimeField()
    priority = fields.IntField()
    group_acls = fields.ListField()



class ProfessionalMember(EmbeddedDocument):
    first_name = StringField()
    last_name = StringField()
    practice = StringField()
    designation = StringField()
    email = StringField()
    phone = StringField()


class  ProfessionalModel(Document):
    uid = fields.StringField()
    name = fields.StringField()
    name_hash = fields.StringField()
    category = fields.StringField()
    subcategory = fields.StringField()
    country = fields.StringField()
    contact_person = fields.StringField()
    contact_phone = fields.StringField()
    email = fields.StringField()
    email_hash = fields.StringField()
    email_verified = fields.BooleanField(default=False)
    email_verification_token = fields.StringField()
    password_token = fields.StringField()
    password_token_timestamp = fields.DateTimeField()
    password_mode = fields.StringField()
    password = fields.StringField()
    account_status = fields.StringField(default='pending')
    joined = fields.DateTimeField()
    address = fields.StringField()
    members = fields.EmbeddedDocumentListField(ProfessionalMember)
    account_info = fields.DictField()
    ciphertext = fields.StringField()
    authtoken = fields.StringField()
    correspondence_address = fields.StringField()
    website = fields.StringField()
    invoice_counter = fields.IntField(default=1)  
    billing_currency = fields.StringField()
    sub_model = fields.StringField(default="free") 
    is_active_sub = fields.BooleanField(default=False) 
    sub_start_date = fields.DateTimeField() 
    sub_end_date = fields.DateTimeField() 
    


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
    
class KYCInformation(EmbeddedDocument):
    kyctype = StringField()
    filename = StringField()
    content_type = StringField()
    size = StringField()
    created = DateTimeField()  
    verifying_agency = StringField()
    kyc_status = StringField()  
    kyc_completion_date = DateTimeField()
    attestation_frequency = IntField()  
    attestation_date = DateTimeField()
    
    
class RelationshipModel(Document):
    consumer = fields.ReferenceField(ConsumerModel)
    biztype = fields.StringField()
    bizuid = fields.StringField()
    reltype = StringField()  
    created = DateTimeField()
    accepted = DateTimeField()
    isaccepted = BooleanField(default=False)
    description = StringField()
    documents = DictField()
    bizdocuments = DictField()
    profile = BooleanField()
    metadata = DictField()
    global_relationship_id = StringField()
    products = DictField()
    status = StringField()
    tc_consent = DictField()
    email = BooleanField()
    mobile = BooleanField()
    kyc_information = EmbeddedDocumentField(KYCInformation)
    group_acls = ListField()
    requester = StringField(default='entity')
    tags = ListField(default=[])
    biztags = ListField(default=[])
    relationship_type = StringField()

    
    
class IdentityDocument(Document):
    consumer = fields.ReferenceField(ConsumerModel)
    category = fields.StringField()  
    doctype = fields.StringField()  
    docid = fields.StringField()  
    expiration_date = fields.DateTimeField()  
    content_type = fields.StringField()  
    filename = fields.StringField()    
    filesize = fields.IntField()  
    created = fields.DateTimeField()
    updated = fields.DateTimeField()    
    metadata = fields.DictField()
    verification_status = fields.StringField() 
    validity_status = fields.StringField()
    verification_vendor = fields.StringField()
    ciphertext = fields.StringField()
    tags = fields.StringField()
    
    
class PersonalDocument(Document):
    consumer = fields.ReferenceField(ConsumerModel)
    category = fields.StringField()  
    name = fields.StringField()  
    description = fields.StringField()  
    expiration_date = fields.DateTimeField()  
    content_type = fields.StringField()  
    filename = fields.StringField()  
    created = fields.DateTimeField()
    updated = fields.DateTimeField()
    metadata = fields.DictField()
    ciphertext = fields.StringField()
    tags = fields.StringField()
    subtags = fields.StringField()    
    
class CertificateDocument(Document):
    consumer = fields.ReferenceField(ConsumerModel)
    category = fields.StringField()                
    name = fields.StringField()                   
    description = fields.StringField()            
    issue_authority = fields.StringField()         
    location = fields.StringField()               
    issue_date = fields.DateTimeField()            
    identification_number = fields.StringField()   
    filename = fields.StringField()    
    filesize = fields.IntField()   
    content_type =fields.StringField()    
    created = fields.DateTimeField()
    updated = fields.DateTimeField()
    metadata = fields.DictField()
    ciphertext = fields.StringField()
    
    
class SpecialRelationship(Document):
    requestor_type = fields.StringField()
    requestor_uid = fields.StringField()
    requestor = fields.GenericLazyReferenceField()
    acceptor_type = fields.StringField()
    acceptor_uid = fields.StringField()
    acceptor = fields.GenericLazyReferenceField()
    created = fields.DateTimeField() 
    accepted_date = fields.DateTimeField()
    isaccepted = fields.BooleanField()
    description = fields.StringField()
    status = fields.StringField()
    reject_reason = fields.StringField()
    requestor_group_acls = fields.ListField()
    acceptor_group_acls = fields.ListField()
    tcfilename = fields.StringField()
    requestor_tags = fields.ListField(default=[])
    acceptor_tags = fields.ListField(default=[])
