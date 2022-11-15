from rest_framework import serializers

from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from account.user.models import User
from .utility import account_activation_token

# serializer for user registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields=['email', 'password', 'password2',]
        extra_kwargs={
            'password':{'write_only':True}
        }
    
    # Validating Password and Confirm Password while Registration
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        
        # check if password is strong
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        return attrs

    def create(self, validate_data):
        return User.objects.create_user(**validate_data)
    

# serializer for user login
class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']

class EmailActivationSerializer(serializers.ModelSerializer):
    # create empty meta
    class Meta:
        model = User
        fields = ['email', 'is_email_verified']

    def validate(self, attrs):
        uid = self.context.get('uid')
        token = self.context.get('token')
        if not uid and token:
            raise serializers.ValidationError("Invalid Token")
        
        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not account_activation_token.check_token(user, token):
                raise serializers.ValidationError("Invalid Token")
            if user.is_email_verified:
                raise serializers.ValidationError("Email is already verified")
            user.is_email_verified = True
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as e:
            raise serializers.ValidationError("Invalid Token")


class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']

  def validate(self, attrs):
    email = attrs.get('email')
    if User.objects.filter(email=email).exists():
      user = User.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://127.0.0.1:8000/api/account/auth/reset-password/'+uid+'/'+token
      print('Password Reset Link', link)
      # Send EMail
      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
      # Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')


            
class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      
      # check if password is strong
      if len(password) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long")

      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user, token)
      raise serializers.ValidationError('Token is not Valid or Expired')