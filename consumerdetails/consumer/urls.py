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
    
]
     