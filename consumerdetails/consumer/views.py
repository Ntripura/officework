from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views import View  
from django import forms
from consumer import models
from consumer import forms
#from consumer import db
#from consumer.db import create_cofferid,consumer_find
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from datetime import timedelta, datetime, timezone
from consumerdetails.auth import authenticate, validate_payload
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
import json
import jwt
import os


def create_cofferid():
    while True:
        uid = os.urandom(8).hex().upper()
        if not models.ConsumerModel.objects.filter(coffer_id=uid):
            return uid

def consumer_find(field, value):
    if field == 'email':
        return models.ConsumerModel.objects.filter(email=value.lower()).first()
    elif field == 'mobile':
        return models.ConsumerModel.objects.filter(mobile=value).first()
    return None

def consumer_by_cofferid(coffer_id):
    con = models.ConsumerModel.objects(coffer_id=coffer_id).first()
    return con

def get_citizenship(citizen):
    citizenship = ['citizen_primary','citizen_second','citizen_third','citizen_fourth']
    for item in citizen:
        if item['index'] in citizenship:
            citizenship.remove(item['index'])
    try:
        return citizenship[0]
    except KeyError as e:
        return None
            

def notify_professional(prof_obj, message, priority=10, group_ids=None):
    prof_notif = models.ProfessionalNotification()
    prof_notif.professional = prof_obj  
    prof_notif.message = message  
    prof_notif.priority = priority  
    prof_notif.status = 'unread'  
    prof_notif.timestamp = datetime.now()   
    if group_ids:  
        prof_notif.group_acls = group_ids
    prof_notif.save()


def audit_professional(prof_uid, name, message):
    audit_event = models.Event()
    audit_event.reference = prof_uid  
    audit_event.name = name.upper()       
    audit_event.message = message    
    audit_event.reference_obj = 'professional'  
    audit_event.timestamp = datetime.now()    
    audit_event .save()


def audit_business(biz_uid, name, message):
    aud_bus = models.Event()
    aud_bus.reference = biz_uid  
    aud_bus.name = name.upper()  
    aud_bus.message = message    
    aud_bus.reference_obj = 'business'  
    aud_bus.timestamp = datetime.now()  
    aud_bus.save()


def audit_consumer(coffer_id, name, message):
    aud_con = models.Event()
    aud_con.reference = coffer_id  
    aud_con.name = name.upper()    
    aud_con.message = message    
    aud_con.reference_obj = 'consumer' 
    aud_con.timestamp = datetime.now()  
    aud_con.save()


class RegisterUser(View):
    form = forms.ConsumerForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(RegisterUser, self).dispatch(request, *args, **kwargs)

    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.ConsumerForm(data)
        
        if form.is_valid():
            firstname = form.cleaned_data['first_name']
            lastname = form.cleaned_data['last_name']
            country = form.cleaned_data['country']
            gender1 = form.cleaned_data['gender']
            mobile_data = form.cleaned_data['mobile']
            email_data = form.cleaned_data['email']
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            confirm_password = form.cleaned_data['confirm_password']
    
            if password != confirm_password:
                return JsonResponse({'error': 'true', 'msg': 'Passwords do not match'})
            hash_password = make_password(password)

            if consumer_find("email", email_data):
                return JsonResponse({'error': True, 'msg': "Email already registered"})
            if consumer_find("mobile", mobile_data):
                return JsonResponse({'error': True, 'msg': "Mobile already registered"})

            coffer_id = create_cofferid()
            user = models.ConsumerModel(coffer_id=coffer_id,first_name=firstname,
                                last_name=lastname,country=country,gender=gender1,
                                email=email_data.lower(),mobile=mobile_data,
                                username=username,password=password,
                                confirm_password=confirm_password,
                                password_hash=hash_password
                                )
            user.save()
            c = models.CofferAPIUser(user='consumer', uid=coffer_id, password=user.password_hash)
            c.save()
            return JsonResponse({'error': 'false', 'msg': 'User created successfully'})
        
        return JsonResponse({'error': 'true', 'msg': 'User creation failed', 'form': form.errors})


class LoginUser(View):
    form = forms.LoginForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(LoginUser, self).dispatch(request, *args, **kwargs)

    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.LoginForm(data)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            
            user = models.ConsumerModel.objects.filter(username=username).first()
            if user and check_password(password, user.password_hash):
                id = str(user.id)
                payload = {
                    "username": user.username,
                    "id": id,
                    "account": "consumer",
                    'exp': datetime.now(timezone.utc) + timedelta(seconds=300)
                }
                SECRET = settings.SECRET_KEY
                token = jwt.encode(payload, SECRET, algorithm='HS256')
                return JsonResponse({'error': 'false', 'token': token.decode("utf-8")})
            
            return JsonResponse({'error': 'true', 'msg': 'Invalid username or password'})

        return JsonResponse({'error': 'true', 'msg': 'Login failed', 'form': form.errors})
    
    
    @authenticate
    def get(self,request,pk=None):
        if pk is not None:
            try:
                dataget = models.ConsumerModel.objects.get(pk=pk)
                cofid = dataget.coffer_id
                consumer = consumer_by_cofferid(cofid)
                if consumer:
                    context = {'id': str(dataget.id),'coffer_id':dataget.coffer_id, 'first_name': dataget.first_name,
                      'last_name':dataget.last_name,'gender':dataget.gender,'email':dataget.email }
                print(context)
                return JsonResponse(context)   
            except Exception as e:
                 print(f"Consumer with pk={pk} not found")
                 return JsonResponse({'error': 'true', 'msg': 'Consumer not found'})
        else:
            data = models.ConsumerModel.objects.all()
            details= []
            for item in data:
                details.append({
                    'id': str(item.id),
                    #'coffer_id':data.coffer_id,
                    'first_name': item.first_name,
                    'last_name':item.last_name,
                    'gender':item.gender,'email':item.email
                })
            return JsonResponse({'consumerdetails': details})
            
            
class UpdateConsumer(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(UpdateConsumer, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def put(self,request,pk=None):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.CounsumerUpdateForm(data)
        
        if pk is not None:
            dataget = models.ConsumerModel.objects.get(pk=pk)
            cofid = dataget.coffer_id
            consumer = consumer_by_cofferid(cofid)
            if consumer:
                if form.is_valid():         
                    dataget.first_name = form.cleaned_data['first_name']
                    dataget.last_name = form.cleaned_data['last_name']
                    dataget.dob = form.cleaned_data['dob']
                    dataget.mobile = form.cleaned_data['mobile']
                    dataget.email = form.cleaned_data['email']
                    if dataget.email:
                        if consumer_find("email", dataget.email):
                            return JsonResponse({'error': True, 'msg': "Email not found"})
                    if dataget.mobile:
                        if consumer_find("mobile",dataget.mobile):
                            return JsonResponse({'error': True, 'msg': "Mobile not found"})
                dataget.save()
                context = {'firstname':dataget.first_name, 'lastname': dataget.last_name,
                          'dob': dataget.dob,'mobile':dataget.mobile,'email': dataget.email}
                print(context)
                return JsonResponse({'error':'false', 'msg':'Consumer updated successfully'})
            else:
               return JsonResponse({'error':'true','msg':'Consumer update failed','form':form.errors})
        else:
            return JsonResponse({'error':'true','msg':'Please provide a valid data'})
        
        
class ConsumerCount(View):
    
    @authenticate
    def get(self, request, *args, **kwargs):
       # print("From count ",request.user)
        #print(request.user['id'])
        con = request.user['id']
        if con:
            notifications = models.ConsumerNotifications.objects(
                consumer=con, status='unread').count()
            return JsonResponse({'error': False, 'data': {'notifications': notifications}})
        return JsonResponse({'error': True, 'msg': 'Account not found.'})
    
    
class NotificationsUpdate(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(NotificationsUpdate, self).dispatch(request, *args, **kwargs)
    
    
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.ConsumerNotificationForm(data)
        status1 = 'unead'
        now = datetime.now(timezone.utc)
        time =now.strftime("%Y-%m-%d %H:%M:%S")
        if form.is_valid():
            message = form.cleaned_data['message']
            priority = form.cleaned_data['priority']
            note = models.ConsumerNotifications(message=message,priority=priority,status=status1,
                                timestamp=time)
            note.save()
            return JsonResponse({'error': 'false', 'msg': 'Notification is created'})
        
        
    @authenticate
    def get(self,request):
      
            data = models.ConsumerNotifications.objects.all()
            details= []
            for item in data:
                details.append({
                    'id': str(item.id),
                    'message': item.message,
                    'priority':item.priority,
                    'status':item.status,
                    'timestamp':item.timestamp
                })
            return JsonResponse({'Notifications': details})
        
    @authenticate
    def delete(self, request,pk=None):
        if pk is not None:
            dataget = models.ConsumerNotifications.objects.get(pk=pk)
            print(dataget)
            dataget.delete()
            return JsonResponse({'error':'false','msg':'Notification deleted successfully'})
        else:
            return JsonResponse({'error':'true','msg':'Notification not deleted'})
       
            
class ReminderDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(ReminderDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.ReminderForm(data)
        
        if form.is_valid():
            message = form.cleaned_data['message']
            target = form.cleaned_data['target']
            now = datetime.now(timezone.utc)
            
            try:
                target_datetime = datetime.strptime(target, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return JsonResponse({'error': 'true', 'msg': 'Invalid target date format. Use YYYY-MM-DD HH:MM:SS.'})

            # Compare target with current time (now)
            if target_datetime <= now:
                return JsonResponse({'error': 'true', 'msg': 'Target must be later than current date and time.'})

            time =now.strftime("%Y-%m-%d %H:%M:%S")
            # if target <= time:
            #     raise forms.ValidationError("Target must be later than today date")
            #     return super(ReminderForm, self).clean()
            rem = models.ConsumerReminder(consumer = request.user['id'],created=time,
                                           message=message,target=target)              
            rem.save()
            return JsonResponse({'error': 'false', 'msg': 'Redminder is created'})
        else:
            return JsonResponse({'error':'true','msg':'Reminder creation failed','form':form.errors})
        
    
    @authenticate
    def get(self,request,pk=None):
            form = forms.ReminderForm()
            data = models.ConsumerReminder.objects.all()
            details= []
            for item in data:
                details.append({
                    'consumer': request.user['id'],
                    'message': item.message,
                    'target':item.target,
                    'created':item.created,
                })
            return JsonResponse({'Reminders': details})
           
           
    @authenticate
    def delete(self, request,pk=None):
        if pk is not None:
            dataget = models.ConsumerReminder.objects.get(pk=pk)
            print(dataget)
            dataget.delete()
            return JsonResponse({'error':'false','msg':'Reminder deleted successfully'})
        else:
            return JsonResponse({'error':'true','msg':'Reminder not deleted'})
        

class ForgotPassword(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(ForgotPassword, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.ForgotPasswordForm(data)
        value = " "
        field = " "
        token = os.urandom(3).hex().upper()
        channel = ""
        
        if form.is_valid():
            em = form.cleaned_data['email']
            mob = form.cleaned_data['mobile']
            if em and consumer_find("email", value):
                value =em
                field = 'email'
                #if consumer_find("email", value):
                   # token = os.urandom(3).hex().upper()
                channel = 'email'
                return JsonResponse({'error': True, 'msg': "Email not found"})
            elif mob and consumer_find("mobile",value):
                value = mob
                field = 'mobile'
                #if consumer_find("mobile",value):
                   # token = os.urandom(3).hex().upper()
                channel = 'mobile'
                return JsonResponse({'error': True, 'msg': "Mobile not found"})
           # con = models.ConsumerReminder(consumer = request.user['id'],email = em,mobile=mob)  
                 
            con = consumer_find(field,value)      
            if con:
                con.password_rest_token = token
                con.password_reset_timestamp = datetime.now(timezone.utc)
                msg = 'Password reset token sent to {}'.format(channel)
                #if channel == 'email':
                   # email = con.email
                   # return JsonResponse({'error': 'false', 'msg': 'Email reset'})
                msg = 'Password reset token sent to {}'.format(channel)
                #if channel == 'mobile':
                    #mobile = con.mobile
                    #return JsonResponse({'error': 'false', 'msg': 'Mobile is reset'})
                con.save()
                return JsonResponse({'error': 'false', 'msg': 'Password is reset'})
        else:
            return JsonResponse({'error':'true','msg':'Reset failed','form':form.errors})
        
        
class IdentityDocumentDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(IdentityDocumentDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.IdocForm(data)
        
        if form.is_valid():
            doctype = form.cleaned_data['doctype']
            docid = form.cleaned_data['docid']
            filename = form.cleaned_data['filename']
            content_type = form.cleaned_data['content_type']
            edate = form.cleaned_data['expiration_date']
            tags = form.cleaned_data['tags']
            verify = "Not-verified"
            vstatus = "valid"
            con = request.user['id']
           # cat = get_citizenship(con.country)
            now = datetime.now(timezone.utc)
            
            try:
                targetdate = datetime.strptime(edate, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return JsonResponse({'error': 'true', 'msg': 'Invalid expiration date format. Use YYYY-MM-DD HH:MM:SS.'})

            if targetdate <= now:
                return JsonResponse({'error': 'true', 'msg': 'Target must be later than current date and time.'})

            time =now.strftime("%Y-%m-%d %H:%M:%S")
           
            idoc = models.IdentityDocument(consumer = con,doctype = doctype,
                                          docid = docid,filename = filename,content_type =content_type,
                                          expiration_date = edate,updated = time,tags = tags,created=time,
                                          verification_status = verify, validity_status = vstatus,
                                         # category = cat
                                           )              
            idoc.save()
            return JsonResponse({'error': 'false', 'msg': 'Idoc is created'})
        else:
            return JsonResponse({'error':'true','msg':'Idoc creation failed','form':form.errors})
        
    
    @authenticate
    def get(self,request,pk=None):
           
            data = models.IdentityDocument.objects.all()
            details= []
            for item in data:
                details.append({
                    'consumer': request.user['id'],
                    'doctype': item.doctype,
                    'docid':item.docid,
                    'filename':item.filename,
                    'content_type': item.content_type,
                    'expiration_date': item.expiration_date,
                    'updated':item.updated,
                    })
            return JsonResponse({'Idocs': details})
           
           
    
    @authenticate
    def put(self,request,pk=None):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.IdocForm(data)
        
        if pk is not None:
            dataget = models.IdentityDocument.objects.get(pk=pk)
            #cofid = dataget.coffer_id
            #consumer = consumer_by_cofferid(cofid)
            if dataget:
                if form.is_valid():         
                    doctype = form.cleaned_data['doctype']
                    docid = form.cleaned_data['docid']
                    filename = form.cleaned_data['filename']
                    content_type = form.cleaned_data['content_type']
                    edate = form.cleaned_data['expiration_date']
                    tags = form.cleaned_data['tags']
                    con = request.user['id']
                    # cat = get_citizenship(con.country)
                    now = datetime.now(timezone.utc)
            
                try:
                    targetdate = datetime.strptime(edate, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    return JsonResponse({'error': 'true', 'msg': 'Invalid expiration date format. Use YYYY-MM-DD HH:MM:SS.'})

                if targetdate <= now:
                    return JsonResponse({'error': 'true', 'msg': 'Target must be later than current date and time.'})

                time =now.strftime("%Y-%m-%d %H:%M:%S")
           
                idoc = models.IdentityDocument(consumer = con,doctype = dataget.doctype,
                                          docid = dataget.docid,filename = dataget.filename,content_type =dataget.content_type,
                                          expiration_date = dataget.edate,updated = dataget.time,tags = dataget.tags,created=dataget.time,
                                    
                                         # category = cat
                                           )              
                idoc.save()
            return JsonResponse({'error': 'false', 'msg': 'Idoc is updated'})
        else:
            return JsonResponse({'error':'true','msg':'Idoc updation failed','form':form.errors})
        
           
    @authenticate
    def delete(self, request,pk=None):
        if pk is not None:
            dataget = models.IdentityDocument.objects.get(pk=pk)
            print(dataget)
            dataget.delete()
            return JsonResponse({'error':'false','msg':'Idoc is deleted successfully'})
        else:
            return JsonResponse({'error':'true','msg':'Idoc not deleted'})
        
        
     
class PersonalDocumentDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(PersonalDocumentDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.PdocForm(data)
        
        if form.is_valid():
            name1 = form.cleaned_data['name']
            description = form.cleaned_data['description']
            filename = form.cleaned_data['filename']
            content_type = form.cleaned_data['content_type']
            edate = form.cleaned_data['expiration_date']
            tags = form.cleaned_data['tags']
            con = request.user['id']
           # cat = get_citizenship(con.country)
            now = datetime.now(timezone.utc)
            
            try:
                targetdate = datetime.strptime(edate, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return JsonResponse({'error': 'true', 'msg': 'Invalid expiration date format. Use YYYY-MM-DD HH:MM:SS.'})

            if targetdate <= now:
                return JsonResponse({'error': 'true', 'msg': 'Target must be later than current date and time.'})

            time =now.strftime("%Y-%m-%d %H:%M:%S")
           
            pdoc = models.PersonalDocument(consumer = con,name = name1,
                                          description = description,filename = filename,content_type =content_type,
                                          expiration_date = edate,updated = time,tags = tags,created=time,
                                            # category = cat
                                           )              
            pdoc.save()
            return JsonResponse({'error': 'false', 'msg': 'Pdoc is created'})
        else:
            return JsonResponse({'error':'true','msg':'Pdoc creation failed','form':form.errors})
        
        
    @authenticate
    def get(self,request,pk=None):
           
            data = models.PersonalDocument.objects.all()
            details= []
            for item in data:
                details.append({
                    'consumer': request.user['id'],
                    'name': item.name,
                    'description':item.description,
                    'filename':item.filename,
                    'content_type': item.content_type,
                    'expiration_date': item.expiration_date,
                    'updated':item.updated,
                    })
            return JsonResponse({'pdocs': details})
        
        
        
    @authenticate
    def put(self,request,pk=None):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.PdocForm(data)
        
        if pk is not None:
            dataget = models.PersonalDocument.objects.get(pk=pk)
            #cofid = dataget.coffer_id
            #consumer = consumer_by_cofferid(cofid)
            if dataget:
                if form.is_valid():         
                    dataget.name = form.cleaned_data['name']
                    dataget.description = form.cleaned_data['description']
                    dataget.filename = form.cleaned_data['filename']
                    dataget.content_type = form.cleaned_data['content_type']
                    dataget.edate = form.cleaned_data['expiration_date']
                    dataget.tags = form.cleaned_data['tags']
                    con = request.user['id']
                    # cat = get_citizenship(con.country)
                    now = datetime.now(timezone.utc)
            
                try:
                    targetdate = datetime.strptime(dataget.edate, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    return JsonResponse({'error': 'true', 'msg': 'Invalid expiration date format. Use YYYY-MM-DD HH:MM:SS.'})

                if targetdate <= now:
                    return JsonResponse({'error': 'true', 'msg': 'Target must be later than current date and time.'})

                dataget.time =now.strftime("%Y-%m-%d %H:%M:%S")
           
                pdoc = models.PersonalDocument(consumer = con,name = dataget.name,
                                          description = dataget.description,filename = dataget.filename,
                                          content_type =dataget.content_type,
                                          expiration_date = dataget.edate,updated = dataget.time,tags = dataget.tags,created=dataget.time,
                                    
                                         # category = cat
                                           )              
                pdoc.save()
                
            return JsonResponse({'error': 'false', 'msg': 'Pdoc is updated'})
        else:
            return JsonResponse({'error':'true','msg':'pdoc updation failed','form':form.errors})
        
           
    @authenticate
    def delete(self, request,pk=None):
        if pk is not None:
            dataget = models.PersonalDocument.objects.get(pk=pk)
            print(dataget)
            dataget.delete()
            return JsonResponse({'error':'false','msg':'Pdoc is deleted successfully'})
        else:
            return JsonResponse({'error':'true','msg':'pdoc not deleted'})     
     
     
     
class CertificateDocumentDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(CertificateDocumentDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.CDocForm(data)
        
        if form.is_valid():
            name= form.cleaned_data['name']
            description = form.cleaned_data['description']
            issueauthority= form.cleaned_data['issue_authority']
            idnumber = form.cleaned_data['identification_number']
            content_type = form.cleaned_data['content_type']
            idate = form.cleaned_data['issue_date']
            loc = form.cleaned_data['location']
            fname = form.cleaned_data['filename']
            con = request.user['id']
           # cat = get_citizenship(con.country)
            now = datetime.now(timezone.utc)
        
            time =now.strftime("%Y-%m-%d %H:%M:%S")
           
            cdoc = models.CertificateDocument(consumer = con,name = name,description = description,
                                           filename = fname,content_type =content_type,
                                          issue_date = idate,updated = time,created=time,location = loc,
                                          issue_authority = issueauthority,identification_number = idnumber
                                            # category = cat
                                           )              
            cdoc.save()
            return JsonResponse({'error': 'false', 'msg': 'cdoc is created'})
        else:
            return JsonResponse({'error':'true','msg':'cdoc creation failed','form':form.errors})
        
        
    @authenticate
    def get(self,request,pk=None):
           
            data = models.CertificateDocument.objects.all()
            details= []
            for item in data:
                details.append({
                    'consumer': request.user['id'],
                    'name': item.name,
                    'description':item.description,
                    'filename':item.filename,
                    'content_type': item.content_type,
                    'issue_date': item.issue_date,
                    'identification_number':item.identification_number,
                    'updated':item.updated,
                    })
            return JsonResponse({'cdocs': details})
        
        
class BusinessDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(BusinessDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.BusinessForm(data)
        
        if form.is_valid():
            uid = os.urandom(3).hex().upper()
            name = form.cleaned_data['name']
            category = form.cleaned_data['category']
            subcategory = form.cleaned_data['subcategory']
            country= form.cleaned_data['country']
            contact_person =  form.cleaned_data['contact_person']
            contact_phone = form.cleaned_data['contact_phone']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            address= form.cleaned_data['address']
            corr_adr =  form.cleaned_data['correspondance_address']
            alias_name = form.cleaned_data['alias_name']
            legal_structure = form.cleaned_data['legal_structure']
            company_website = form.cleaned_data['company_website']
            registration_no= form.cleaned_data['registration_no']
            now = datetime.now(timezone.utc)
            time =now.strftime("%Y-%m-%d %H:%M:%S")
            #con = request.user['id']   
                
            bdata = models.BusinessModel(uid = uid,name = name, category = category, subcategory = subcategory,
                            country = country, contact_person = contact_person,contact_phone = contact_phone,
                            email = email,password = password, address = address,joined = time,
                            correspondance_address = corr_adr,alias_name = alias_name,
                            legal_structure = legal_structure, company_website = company_website,
                            registration_number = registration_no)
            bdata.save()
            return JsonResponse({'error':'false', 'msg':'Business Data created'})  
        else:
                return JsonResponse({'error':'true','msg':'Business creation failed','form':form.errors})
    
    
    
class ProfessionalDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(ProfessionalDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.ProfessionalForm(data)
        
        if form.is_valid():
             if form.is_valid():
                uid = os.urandom(3).hex().upper()
                name = form.cleaned_data['name']
                category = form.cleaned_data['category']
                subcategory = form.cleaned_data['subcategory']
                country= form.cleaned_data['country']
                contact_person =  form.cleaned_data['contact_person']
                contact_phone = form.cleaned_data['contact_phone']
                email = form.cleaned_data['email']
                password = form.cleaned_data['password']
                address= form.cleaned_data['address']
                correspondence_address =  form.cleaned_data['correspondence_address']
                website = form.cleaned_data['website']
                now = datetime.now(timezone.utc)
                time =now.strftime("%Y-%m-%d %H:%M:%S")
                #consumer_id = request.user['id']
                
                pdata = models.ProfessionalModel(uid = uid, name = name, category = category, subcategory = subcategory,
                            country = country, contact_person = contact_person,contact_phone = contact_phone,
                            email = email,password = password,  address = address,
                            correspondence_address = correspondence_address,
                            website = website
                            )
                pdata.save()
                return JsonResponse({'error':'false', 'msg':'Professional Data created'})  
        else:
                return JsonResponse({'error':'true','msg':'Professional creation failed','form':form.errors})     
    
            
        
        
        
class SpecialRelationshipDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(SpecialRelationshipDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.CDocForm(data)
        
        if form.is_valid():
            name= form.cleaned_data['name']
            description = form.cleaned_data['description']
            issueauthority= form.cleaned_data['issue_authority']
            idnumber = form.cleaned_data['identification_number']
            content_type = form.cleaned_data['content_type']
            idate = form.cleaned_data['issue_date']
            loc = form.cleaned_data['location']
            fname = form.cleaned_data['filename']
            con = request.user['id']
           # cat = get_citizenship(con.country)
            now = datetime.now(timezone.utc)
        
            time =now.strftime("%Y-%m-%d %H:%M:%S")
           
            cdoc = models.CertificateDocument(consumer = con,name = name,description = description,
                                           filename = fname,content_type =content_type,
                                          issue_date = idate,updated = time,created=time,location = loc,
                                          issue_authority = issueauthority,identification_number = idnumber
                                            # category = cat
                                           )              
            cdoc.save()
            return JsonResponse({'error': 'false', 'msg': 'cdoc is created'})
        else:
            return JsonResponse({'error':'true','msg':'cdoc creation failed','form':form.errors})
        
        
class RelationshipDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(RelationshipDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self,request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.RequestRelationForm(data)
        
        if form.is_valid():
            eId= form.cleaned_data['entityId']
            description = form.cleaned_data['description']
            btype =form.cleaned_data['biztype']
            conid = request.user['id']
            reltype = 'consumer'
            isaccepted = 'True'
            status = 'accepted_by_consumer'
            if btype == 'business':
                dataget = models.BusinessModel.objects.filter(uid=eId).first()
            else:
                dataget = models.ProfessionalModel.objects.filter(uid = eId).first()
            now = datetime.now(timezone.utc)
            time =now.strftime("%Y-%m-%d %H:%M:%S")
           
            rel = models.RelationshipModel(consumer = conid,biztype = btype,bizuid = dataget.uid,
                                          reltype =reltype, description = description,created = time,
                                          accepted =time,isaccepted = isaccepted,status =status)                                                                 
            rel.save()
                
            return JsonResponse({'error': 'false', 'msg': 'Relationship is created'})
        else:
            return JsonResponse({'error':'true','msg':'Relationship not created','form':form.errors})
        
        
        
    @authenticate
    def put(self,request,pk=None):
       
        con = request.user['id']
        name = con.name
        if con:
            if pk is not None:
                dataget = models.RelationshipModel.objects.get(pk=pk)
           
                if dataget:
                    msg = ''
                    if 'isacepted' in dataget:
                        dataget.isaccepted = dataget['isaccepted']
                        dataget.status = 'accepted_by_user'
                        dataget.save()
                        if dataget.biztype == 'prof':
                            msg = "{} has accepted the relationship request.".format(name, dataget.reltype)
                            prof = models.ProfessionalModel.objects(uid=dataget.bizuid).first()
                            notify_professional( prof, msg, group_ids=dataget.group_acls)
                            try:
                                audit_professional(prof.uid, 'relationship', msg)
                            except Exception as e:
                                print("Error creating an audit trail for professional")
                                prof_name = prof.name
                                msg = "You have acceptped relationship with {}.".format(
                                prof_name)
                            try:
                                audit_consumer(con, 'relationship', msg)
                            except Exception as e:
                                print( "Error creating an audit trail for consumer")
                                msg = "Relationship with {} was established successfully.".format(
                                prof_name)
                            return {'error': False, 'msg': msg}
                        if dataget.biztype == 'business':
                            msg = "{} has accepted the relationship request.".format(name, dataget.reltype)
                            buss = models.BusinessModel.objects(uid=dataget.bizuid).first()
                            notify_professional( buss, msg, group_ids=dataget.group_acls)
                            try:
                                audit_professional(buss.uid, 'relationship', msg)
                            except Exception as e:
                                print("Error creating an audit trail for professional")
                                bus_name = buss.name
                                msg = "You have acceptped relationship with {}.".format(
                                bus_name)
                            try:
                                audit_consumer(con, 'relationship', msg)
                            except Exception as e:
                                print( "Error creating an audit trail for consumer")
                                msg = "Relationship with {} was established successfully.".format(
                                bus_name)
                            return {'error': False, 'msg': msg}
                   
                
            return JsonResponse({'error': 'false', 'msg': 'Relationship is updated'})
        else:
            return JsonResponse({'error':'true','msg':'Relationship updation failed'})
        
           
       
            
            
