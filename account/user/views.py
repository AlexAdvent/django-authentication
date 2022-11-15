from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .serializers import UpdatePasswordSerializer

# update user password
class UpdatePassword(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        user = request.user
        serializer = UpdatePasswordSerializer(data=request.data, context={'user':request.user} )
        serializer.is_valid(raise_exception=True)
        return Response({'message': "Password changed successfully"})
