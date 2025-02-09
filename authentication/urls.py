from django.contrib import admin
from django.urls import path,include
from . import views

urlpatterns = [
   path('',views.home,name ="home"),
   path('signup',views.signup,name="signup"),
   path('signin',views.signin,name="signin"),
   path('signout',views.signout,name="signout"),
   path('activate/<uid64>/<token>', views.activate, name="activate"),
   path('forgot_password/', views.forgot_password, name='forgot_password'),
   path('profile/', views.profile, name='profile'),
   path('change_password/', views.change_password, name='change_password'),  # Add this line
   path('reset_password/<str:uid64>/<str:token>/', views.reset_password, name='reset_password'),
   path('dashboard', views.dashboard, name="dashboard")  # Add this line
   
]
