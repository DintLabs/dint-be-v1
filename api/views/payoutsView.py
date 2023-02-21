from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema, uritemplate
from rest_framework.viewsets import ModelViewSet

from api.services.payouts import PayoutsService

payoutsService = PayoutsService()

class UserPayouts(APIView):
    """
    APIs for Fetching the Payouts
    """

    def post(self, request, format=None):
        """
        Request For Payouts By Token.
        """
        result = payoutsService.request_payouts_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
    def get(self, request, format=None):
        """
        Get Requested Payouts 
        """
        result = payoutsService.get_all_requested_payouts(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserPayoutsByToken(APIView):
    def get(self, request, format=None):
        """
        Get Payouts By User Id
        """
        result = payoutsService.get_payouts_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
   