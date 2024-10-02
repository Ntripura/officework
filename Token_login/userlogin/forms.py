from django.forms import fields  
from userlogin import models  
from django import forms  
from userlogin.models import ConsumerModel, DummyRelationModel,BusinessModel,ProfessionalModel,IdentityDocumentModel
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
      
      
class BusinessForm(forms.ModelForm):

    name = forms.CharField()  
    category = forms.CharField()
    subcategory = forms.CharField() 
    country = forms.CharField()
    contact_person = forms.CharField()
    contact_phone = forms.CharField()
    email = forms.EmailField()
    password = forms.CharField()
    account_status = forms.CharField() 
    joined= forms.DateTimeField()
    address = forms.CharField()
    correspondance_address = forms.CharField()
    alias_name = forms.CharField() 
    legal_structure = forms.CharField()
    company_website = forms.CharField()  
    registration_no = forms.CharField()  #GST No
    #aboutus = forms.CharField()
    #addons = forms.CharField()
    
    class Meta:
       model = BusinessModel
       fields = ['name','category','subcategory','country',
                 'contact_person','contact_phone','email','password',
                 'address','correspondance_address','account_status',"joined",
                 'alias_name','legal_structure','company_website','registration_no']
       
       
       
class ProfessionalForm(forms.ModelForm):

    name = forms.CharField()  
    category = forms.CharField()
    subcategory = forms.CharField() 
    country = forms.CharField()
    contact_person = forms.CharField()
    contact_phone = forms.CharField()
    email = forms.EmailField()
    password = forms.CharField()
    account_status = forms.CharField() 
    joined= forms.DateTimeField()
    address = forms.CharField()
    correspondance_address = forms.CharField()
    alias_name = forms.CharField() 
    legal_structure = forms.CharField()
    company_website = forms.CharField()  
    registration_no = forms.CharField()  #GST No
    #aboutus = forms.CharField()
    #addons = forms.CharField()
    
    class Meta:
       model = ProfessionalModel
       fields = ['name','category','subcategory','country',
                 'contact_person','contact_phone','email','password',
                 'address','correspondance_address','account_status',"joined",
                 'alias_name','legal_structure','company_website','registration_no']
       
       
class IdentityDocumentForm(forms.ModelForm):

    doctype = forms.CharField()  
    docid = forms.CharField()
    expiration_date = forms.CharField() 
    filename = forms.CharField()
    content_type = forms.CharField()
    tags = forms.CharField()
   
    
    
    class Meta:
       model = IdentityDocumentModel
       fields = [
                 'doctype','docid','expiration_date','filename',
                 'content_type','tags'
                ]
       
            
      