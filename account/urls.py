
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('auth/', include('account.authentication.urls')),
    path('user/', include('account.user.urls')),
]
