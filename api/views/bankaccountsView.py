from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema, uritemplate
from rest_framework.viewsets import ModelViewSet

from api.services.bankaccounts import BankAccountsService

bankaccountsService = BankAccountsService()

class UserBankAccounts(APIView):
    """
    APIs for Fetching the user bankaccounts by Token
    """

    def post(self, request, format=None):
        """
        Add User bankaccounts By Token.
        """
        result = bankaccountsService.add_bank_accounts_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
    def get(self, request, format=None):
        """
        Get User Bankaccount By Token
        """
        result = bankaccountsService.get_bank_accounts_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, id, format=None):
        """
        Get User Bankaccount By Token
        """
        result = bankaccountsService.update_bank_accounts_by_token(request, id, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
class UserRequestPayouts(APIView):
    """
    API To Fetch Payouts list requested
    """
    def post(self, request, format=None):
        """
        Request payouts.
        """
        result = bankaccountsService.add_to_request(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
