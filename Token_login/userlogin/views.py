from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views import View  
from django import forms
from userlogin import models
from userlogin import forms

from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from datetime import timedelta, datetime, timezone
from Token_login.auth import authenticate, validate_payload
from django.contrib.auth.hashers import make_password, check_password
import json
import jwt
import os

from bson import ObjectId

# Create your views here.
class RegisterUser(View):
    
    form = forms.ConsumerForm
    
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(RegisterUser, self).dispatch(request, *args, **kwargs)
   
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.ConsumerForm(data)
        if form.is_valid():    
            #     aa= models.ConsumerModel(password_hash=hashpass) This way it is saving hash only in other object
            #     aa.save()
            #     print(aa.password_hash)
            firstname = form.cleaned_data['first_name']
            lastname = form.cleaned_data['last_name']
            mobile = form.cleaned_data['mobile']
            email = form.cleaned_data['email']
            username = form.cleaned_data['username']
            password = make_password(form.cleaned_data['password'])
            confirm_password =form.cleaned_data['confirm_password']
            check_password(password,data['password'])
           # print(check)
            #form.password =make_password(data['password'])
            #print(password)
            #form.save()
            register = models.ConsumerModel(first_name = firstname, last_name = lastname, email = email, 
                                            mobile = mobile, username = username, password = password,
                                            confirm_password = confirm_password, password_hash = password)
            register.save()
            print(register)
            return JsonResponse({'error':'false', 'msg':'user created successfully'})
        else:
            return JsonResponse({'error':'true','msg':'user creation failed','form':form.errors})
    
class LoginUser(View):
    form = forms.LoginForm
    
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(LoginUser, self).dispatch(request, *args, **kwargs)
    
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.LoginForm(data)
        header = {
            "accept": "application/json",
            "Authorization": "Bearer_Token"
            }
        #dataget = models.ConsumerModel.objects.get(email)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = models.ConsumerModel.objects.get(username = username, password =password)
            if user:
                id = str(user._id)
                payload ={"username":user.username,"password":user.password,"id":id,'exp': datetime.now(timezone.utc) + timedelta(seconds=300)}
                SECRET= settings.SECRET_KEY
                request.user = payload.get('user')
                #if verify_password(login_password, hash_password):
                token = jwt.encode(payload, SECRET, algorithm='HS256',headers=header)
                print(data)
                print(token)
                print(request.user)
                #print(request.user._id)
                return JsonResponse({'error':'false', 'token':token.decode()}) 
            else:
                return JsonResponse({'error':'true', 'msg':'Invalid username or password'})
        else:
            return JsonResponse({'error':'true','msg':'user login failed','form':form.errors})
    
    
class UserDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(UserDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def get(self,request,pk=None):
       form = forms.ConsumerForm()
       print("From get",request.user)
       if pk is not None:
            #dataget = models.ConsumerModel.objects.get(pk=request.user['id'])
            dataget = models.ConsumerModel.objects.get(pk=ObjectId(pk))
            context = {'first_name':dataget.first_name, 'last_name': dataget.last_name, 'mobile':dataget.mobile,'email': dataget.email}
            print(context)
            return JsonResponse(context)   
       else:
            data = models.ConsumerModel.objects.get(self.request.user)
            print(data)
            context = {'user': data}
            print(context)
            return JsonResponse(context)   

class DummyRelationDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(DummyRelationDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        dummy = None
        data = json.loads(request.body.decode('utf-8'))
        form = forms.DummyRelationForm(data)
        print("From dummy post",request.user)
        print(request.user['id'])
        if form.is_valid():
            firmname = form.cleaned_data['firm_name']
            firmaddress = form.cleaned_data['firm_address']
            account_id = form.cleaned_data['account_id']
            biz_no = form.cleaned_data['biz_identification_no']
            others =  form.cleaned_data['others']
            now = datetime.now(timezone.utc)
            time =now.strftime("%Y-%m-%d %H:%M:%S")
            consumer_id = request.user['id']
            con = models.DummyRelationModel(consumer_id = consumer_id,created = time,
                                            firm_name =firmname, firm_address = firmaddress,
                                            account_id = account_id, biz_identification_no = biz_no,
                                            others = others)
            c =con.save()
            #form.save()
            
            return JsonResponse({'error':'false', 'msg':'Dummy relationship created'})  
        else:
            return JsonResponse({'error':'true','msg':'Dummy relation creation failed','form':form.errors})
    
    
    @authenticate
    def get(self,request,pk=None):
       form = forms.DummyRelationForm()
       if pk is not None:
            dataget = models.DummyRelationModel.objects.get(pk=ObjectId(pk))
            context = {'firm_name':dataget.firm_name, 'firm_address': dataget.firm_address,
                       'account_id':dataget.account_id,'biz_no': dataget.biz_identification_no,
                       'others':dataget.others}
            print(context)
            return JsonResponse(context)   
       else:
            data = models.DummyRelationModel.objects.all()
            print(data)
            context = {'dummy relationship': list(data.values('firm_name',
                            'firm_address',
                            'account_id',
                            'created',
                            'biz_identification_no',
                            'others' ))}
            print(context)
            return JsonResponse(context)   
    
    
class ReminderDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(ReminderDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        form = forms.ReminderForm(data)
        print("From reminder post",request.user)
        print(request.user['id'])
        if form.is_valid():
            message = form.cleaned_data['message']
            target = form.cleaned_data['target']
            now = datetime.now(timezone.utc)
            time =now.strftime("%Y-%m-%d %H:%M:%S")
            if target <= time:
                raise forms.ValidationError("Target must be later than today date")
                return super(ReminderForm, self).clean()
            consumer_id = request.user['id']
            con = models.ReminderModel(consumer_id = consumer_id,created = time,
                                            message = message, target = target)
            con.save()                               
            #form.save()
            return JsonResponse({'error':'false', 'msg':'Reminder created'})  
        else:
            return JsonResponse({'error':'true','msg':'Reminder creation failed','form':form.errors})
        
    
    @authenticate
    def get(self,request,pk=None):
       form = forms.ReminderForm()
       if pk is not None:
            dataget = models.ReminderModel.objects.get(pk=ObjectId(pk))
            context = {'consumer':dataget.consumer, 'created': dataget.created,
                       'message':dataget.message,'target': dataget.target}
            print(context)
            return JsonResponse(context)   
       else:
            data = models.ReminderModel.objects.all()
            print(data)
            context = {'reminders': list(data.values('consumer','created',
                                                     'message','target',))}
            print(context)
            return JsonResponse(context)   
    
    
    
class PDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(PDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        print("From business post",request.user)
        print(request.user['id'])
        if data['category'] == "prof":
            form = forms.ProfessionalForm(data)
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
                correspondance_address =  form.cleaned_data['correspondance_address']
                alias_name = form.cleaned_data['alias_name']
                legal_structure = form.cleaned_data['legal_structure']
                company_website = form.cleaned_data['company_website']
                registration_no= form.cleaned_data['registration_no']
                now = datetime.now(timezone.utc)
                time =now.strftime("%Y-%m-%d %H:%M:%S")
                created = time
                con = models.ProfessionalModel(uid = uid,name = name, category = category, 
                                           subcategory = subcategory,country = country, 
                            contact_person = contact_person,contact_phone = contact_phone,
                            email = email,password = password, address = address,
                            correspondance_address = correspondance_address,
                            alias_name = alias_name,legal_structure = legal_structure,
                            company_website = company_website, joined = created,
                            registration_no = registration_no)
                con.save()
                return JsonResponse({'error':'false', 'msg':'Professional Data created'})  
            else:
                return JsonResponse({'error':'true','msg':'Professional creation failed','form':form.errors})     
    
        
class BDetails(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(BDetails, self).dispatch(request, *args, **kwargs)
    
    @authenticate
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        print("From business post",request.user)
        print(request.user['id'])
        if data['category'] == "business":
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
                correspondance_address =  form.cleaned_data['correspondance_address']
                alias_name = form.cleaned_data['alias_name']
                legal_structure = form.cleaned_data['legal_structure']
                company_website = form.cleaned_data['company_website']
                registration_no= form.cleaned_data['registration_no']
                now = datetime.now(timezone.utc)
                time =now.strftime("%Y-%m-%d %H:%M:%S")
                created =time
                con = models.BusinessModel(uid = uid,name = name, category = category, 
                                           subcategory = subcategory,country = country, 
                            contact_person = contact_person,contact_phone = contact_phone,
                            email = email,password = password, address = address,
                            correspondance_address = correspondance_address,
                            alias_name = alias_name,legal_structure = legal_structure,
                            company_website = company_website, joined = created,
                            registration_no = registration_no)
                con.save()
                return JsonResponse({'error':'false', 'msg':'Business Data created'})  
            else:
                return JsonResponse({'error':'true','msg':'Business creation failed','form':form.errors})        
            
            
        