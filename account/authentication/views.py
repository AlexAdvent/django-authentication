from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError

from .serializers import UserRegistrationSerializer, UserLoginSerializer, EmailActivationSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from .utility import account_activation_token
from account.user.models import User
from .utility import get_tokens_for_user, get_refresh_token_from_action_token





# view for refreshing token
class TokenRefreshView(APIView):
  def post(self, request):
    try:
      refresh_token = request.data['refresh']
      tokens = get_refresh_token_from_action_token(refresh_token)
      return Response(tokens, status=status.HTTP_200_OK)
    except Exception as e:
      return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Create registration view.
class UserRegistrationView(APIView):
  def post(self, request, format=None):
      serializer = UserRegistrationSerializer(data=request.data)
      serializer.is_valid(raise_exception=True)
      user = serializer.save()
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = get_tokens_for_user(user)
      email_activation_token = account_activation_token.make_token(user)
      print('email_activation_token', email_activation_token)
      link = 'http://127.0.0.1:8000/api/account/auth/email-activation/'+uid+'/'+email_activation_token
      print('Password Reset Link', link)

      return Response({'token':token, 'msg':'Registration Successful', 'is_email_verified': False, 'email_activation_link': link }, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    print('email', email, 'password', password)
    user = authenticate(email=email, password=password)
    print('user', user)

    if user is not None:
      # get is_email_verified
      is_email_verified = user.is_email_verified
      token = get_tokens_for_user(user)

      return Response({'token':token, 'msg':'Login Success', 'is_email_verified': is_email_verified}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'email':['email does not exist']}}, status=status.HTTP_404_NOT_FOUND)

#  Create email activation view
class EmailActivationView(APIView):
    def post(self, request, uid, token, format=None):
        if not uid and token:
            return Response({'error':'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not account_activation_token.check_token(user, token):
                return Response({'error':'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)
            if user.is_email_verified:
                return Response({'msg':'Email Already Verified'}, status=status.HTTP_400_BAD_REQUEST)
            user.is_email_verified = True
            user.save()
            # account_activation_token.delete_token(user) TODO: Delete Token
            return Response({'msg':'Email Verified Successfully'}, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError as e:
            return Response({'error':'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)

# send email password reset link
class SendPasswordResetEmailView(APIView):
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)