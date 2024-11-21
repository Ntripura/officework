from django import forms
from datetime import datetime
from consumer import models
from django.core.exceptions import ValidationError


class LoginForm(forms.Form):
      username = forms.CharField()
      password = forms.CharField()


class ConsumerForm(forms.Form):
    mobile = forms.CharField(required=False)
    first_name = forms.CharField()
    last_name = forms.CharField()
    dob = forms.DateTimeField(required=False)
    country = forms.CharField()
    gender = forms.CharField(required=False)
    username = forms.CharField()
    password = forms.CharField()
    email = forms.EmailField(required=False)
    confirm_password = forms.CharField()
    
    def clean_data(self):
        data = super().clean()
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        mobile = data.get('mobile')
        email = data.get('email')
        username = data.get('username')
        if not forms.instance:
           # if User.objects.filter(username=cleaned_data["username"].exists():
            if models.ConsumerModel.objects.filter(username=username, email=email).exists():
                raise forms.ValidationError('username and email already exists.')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        if password!= confirm_password:
            raise ValidationError('Invalid password')
     

class CounsumerUpdateForm(forms.Form):
    first_name = forms.CharField(required=False)
    last_name = forms.CharField(required=False)
    dob = forms.DateTimeField(required=False)
    mobile = forms.CharField(required=False)
    email = forms.EmailField(required=False)


class ConsumerNotificationForm(forms.Form):
    message = forms.CharField()
    priority = forms.IntegerField()
    
    
class ReminderForm(forms.Form):
    message = forms.CharField()
    target = forms.CharField()
    
class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(required=False)
    mobile = forms.CharField(required=False)
    
    
class IdocForm(forms.Form):
    doctype = forms.CharField()
    docid = forms.CharField()
    content_type = forms.CharField()
    filename = forms.CharField()
    expiration_date = forms.CharField() 
    tags = forms.CharField()


class PdocForm(forms.Form):
    name = forms.CharField()
    description = forms.CharField()
    content_type = forms.CharField()
    filename = forms.CharField()
    expiration_date = forms.CharField() 
    tags = forms.CharField()

