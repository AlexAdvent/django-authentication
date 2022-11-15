from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken 
import six

class TokenGenerator(PasswordResetTokenGenerator):  
    def _make_hash_value(self, user, timestamp):  
        return (  
            six.text_type(user.pk) + six.text_type(timestamp) +  
            six.text_type(user.is_active) + six.text_type(user.is_email_verified)
        )  
account_activation_token = TokenGenerator()


# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

# generate refresh token from action token
def get_refresh_token_from_action_token(action_token):
  refresh = RefreshToken(action_token)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }