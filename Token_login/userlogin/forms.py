from django.forms import fields  
from userlogin import models  
from django import forms  
from userlogin.models import ConsumerModel, DummyRelationModel
from django.core.exceptions import ValidationError
  

class ConsumerForm(forms.ModelForm):   
    first_name = forms.CharField()
    last_name = forms.CharField(required=False)
    mobile = forms.CharField(required=False)
    email = forms.EmailField(required=False)
    username = forms.CharField()
    password = forms.CharField()
    confirm_password = forms.CharField()
    
    class Meta:
       model = ConsumerModel
       fields = ['first_name','last_name','mobile','email','username','password','confirm_password']
       
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
     
class LoginForm(forms.ModelForm):
      username = forms.CharField()
      password = forms.CharField()
      class Meta:
       model = ConsumerModel
       fields = ['username','password']
      
            
            
class DummyRelationForm(forms.ModelForm):
      firm_name = forms.CharField()
      firm_address = forms.CharField()
      account_id = forms.CharField()
      biz_identification_no =forms.CharField()
      others = forms.CharField()
      class Meta:
       model = DummyRelationModel
       fields = ['firm_name','firm_address','account_id','biz_identification_no','others']
      