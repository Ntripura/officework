from django.urls import path
from consumer import views
from consumer import models

urlpatterns = [ 
    
   path('signup/', views.RegisterUser.as_view()),
   path('login/', views.LoginUser.as_view()),
   path('userdetails/<str:pk>/', views.LoginUser.as_view()),
   path('userdetails/',views.LoginUser.as_view()),
   path('userupdate/<str:pk>/',views.UpdateConsumer.as_view()), 
   path('count/<cofferid>/',views.ConsumerCount.as_view()), 
   path('create_notification/', views.NotificationsUpdate.as_view()),
   path('notifications/', views.NotificationsUpdate.as_view()),
   path('notification_delete/<str:pk>/', views.NotificationsUpdate.as_view()),
   path('rem_create/',views.ReminderDetails.as_view()),  #post
   path('reminders/',views.ReminderDetails.as_view()),  #get
    path('rem_delete/<str:pk>/', views.ReminderDetails.as_view()),
    path('pswd_reset/',views.ForgotPassword.as_view()),  #post
   path('idoc_create/',views.IdentityDocumentDetails.as_view()),  #post
   path('idocs/',views.IdentityDocumentDetails.as_view()), 
   path('idoc_edit/<str:pk>/',views.IdentityDocumentDetails.as_view()), 
   path('idoc_delete/<str:pk>/', views.IdentityDocumentDetails.as_view()),
   path('pdoc_create/',views.PersonalDocumentDetails.as_view()),  #post
   path('pdocs/',views.PersonalDocumentDetails.as_view()), 
   path('pdoc_edit/<str:pk>/',views.PersonalDocumentDetails.as_view()), 
   path('pdoc_delete/<str:pk>/', views.PersonalDocumentDetails.as_view()),
   path('cdoc_create/',views.CertificateDocumentDetails.as_view()),  #post
   path('cdocs/',views.CertificateDocumentDetails.as_view()), 
   path('bdata_create/',views.BusinessDetails.as_view()),  #post
   path('pdata_create/',views.ProfessionalDetails.as_view()),  #post
   path('relation_create/',views.RelationshipDetails.as_view()),  #post
   path('relation_edit/<str:pk>/', views.RelationshipDetails.as_view())
    
    
]
     