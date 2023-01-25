from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema, uritemplate
from rest_framework.viewsets import ModelViewSet

from api.models import UserReferralWallet
from api.services.wisetransfer import WiseTransferService

wiseService = WiseTransferService()

class WiseRecepientsView(APIView):
    """
    APIs for Fetching the user bankaccounts by Token
    """

    def get(self, request, format=None):
        """
        Get User bankaccounts By Token.
        """
        result = wiseService.get_recipients_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    # def put(self, request, pk, format=None):
    #     """
    #     update user status
    #     """
    #     result = wiseService.update_recipient_account_by_token(request, pk, format=None)
    #     return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create User bankaccounts By Token.
        """
        result = wiseService.create_recipients_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk, format=None):
        """
        Delete User bankaccounts By Token.
        """
        
        result = wiseService.delete_recipient_account_by_token(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class WiseQuotesView(APIView):

     def get(self, request, format=None):
        """
        Get User Wise Quotes By Token
        """
        result = wiseService.get_quotes_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

     def post(self, request, format=None):
        """
        Create User Wise Quotes By Token
        """
        result = wiseService.create_quotes_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class WiseTransferView(APIView):

    #  def get(self, request, format=None):
    #     """
    #     Get User Wise Quotes By Token
    #     """
    #     result = wiseService.get_quotes_by_token(request, format=None)
    #     return Response(result, status=status.HTTP_200_OK)

     def post(self, request, format=None):
        """
        Create User Wise Transfer By Token
        """
        result = wiseService.create_wise_transfer_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class WisePaymentView(APIView):

     def post(self, request, format=None):
        """
        Create User Wise Transfer By Token
        """
        result = wiseService.create_wise_payment_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)