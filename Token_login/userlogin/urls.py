from django.urls import path
from userlogin import views
from userlogin import models

urlpatterns = [
    path('signup/', views.RegisterUser.as_view()),
    path('login/', views.LoginUser.as_view()),
    #path('userdetails/',views.UserDetails.as_view())
    path('userdetails/<str:pk>/', views.UserDetails.as_view()),
    path('dummycreate/',views.DummyRelationDetails.as_view()),  #post
    path('dummyget/',views.DummyRelationDetails.as_view())  #get
   # path('edit/<str:pk>/', views.Employee.as_view()),
    # path('editpatch/<str:pk>/', views.Employee.as_view()),
    # path('delete/<str:pk>/', views.Employee.as_view()),
]