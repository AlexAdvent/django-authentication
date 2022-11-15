from django.urls import path
from .views import UpdatePassword
urlpatterns = [
    path('changedpassword/', UpdatePassword.as_view(), name='changedpassword'),
]