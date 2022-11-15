from django.urls import path
from .views import TokenRefreshView, UserRegistrationView, UserLoginView, EmailActivationView, SendPasswordResetEmailView, UserPasswordResetView
urlpatterns = [
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('register', UserRegistrationView.as_view(), name='register'),
    path('login', UserLoginView.as_view(), name='login'),
    path('email-activation/<uid>/<token>', EmailActivationView.as_view(), name='email-activation'),
    path('send-reset-password-email', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>', UserPasswordResetView.as_view(), name='reset-password'),
]