from rest_framework import serializers

from .models import User


class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)


    class Meta:
        fields = ['old_password', 'new_password', 'new_password2']

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        password = attrs.get('new_password')
        password2 = attrs.get('new_password2')

        # chekc old password
        if not self.context['user'].check_password(old_password):
            raise serializers.ValidationError({'old_password': 'Wrong password.'})
            

        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs




 