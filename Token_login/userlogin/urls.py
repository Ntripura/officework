from django.urls import path
from userlogin import views
from userlogin import models


urlpatterns = [
    path('signup/', views.RegisterUser.as_view()),
    path('login/', views.LoginUser.as_view()),
    #path('userdetails/',views.UserDetails.as_view())
    path('userdetails/<str:pk>/', views.UserDetails.as_view()),
    path('userdetails/',views.UserDetails.as_view()),
    path('dummycreate/',views.DummyRelationDetails.as_view()),  #post
    path('dummyget/',views.DummyRelationDetails.as_view()),  #get
    path('remindercreate/',views.ReminderDetails.as_view()),  #post
    path('reminders/',views.ReminderDetails.as_view()),  #get
    path('businesscreate/',views.BusinessDetails.as_view()),  #post
    path('bizdetails/<str:pk>/',views.BusinessDetails.as_view()),
    path('pbizdetails/<str:pk>/',views.ProfessionalDetails.as_view()),
    path('getdetails/',views.BusinessDetails.as_view()),#post
    path('getrelation/',views.RelationshipDetails.as_view()),
    path('idoc_create/',views.IdentityDocumentDetails.as_view()),  #post
    path('get_idoc/',views.IdentityDocumentDetails.as_view()), 
    path('edit_idoc/<str:pk>/',views.IdentityDocumentDetails.as_view()), 
    path('idoc_delete/<str:pk>/', views.IdentityDocumentDetails.as_view()),
    path('pdoc_create/',views.PersonalDocumentDetails.as_view()),  #post
    path('get_pdoc/',views.PersonalDocumentDetails.as_view()), 
    path('edit_pdoc/<str:pk>/',views.PersonalDocumentDetails.as_view()), 
    path('pdoc_delete/<str:pk>/', views.PersonalDocumentDetails.as_view()),
    path('cdoc_create/',views.CertificateDocumentDetails.as_view()),  #post
    path('get_cdoc/',views.CertificateDocumentDetails.as_view()), 
    path('edit_cdoc/<str:pk>/',views.CertificateDocumentDetails.as_view()), 
    path('cdoc_delete/<str:pk>/', views.CertificateDocumentDetails.as_view()),
]