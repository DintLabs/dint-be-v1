from rest_framework import status
from api.utils.messages.commonMessages import *
from api.models.BankAccountsModel import UserBankAccounts
from api.serializers.bankaccounts import UserBankAccountsSerializer
from .bankaccountsBaseService import BankAccountsBaseService

class BankAccountsService(BankAccountsBaseService):
    """
    Allow any user (authenticated or not) to access this url 
    """
    def __init__(self):
        pass
    
    def add_bank_accounts_by_token(self, request, format=None):
        account_exist = UserBankAccounts.objects.filter(accountNumber=request.data['accountNumber'])
        if not account_exist:
            serializer = UserBankAccountsSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                bank_obj = UserBankAccounts.objects.filter(user = request.user)
                if (len(bank_obj) == 1):
                    primary_acnt = UserBankAccounts.objects.filter(user = request.user).update(primary = True)
                res_data = UserBankAccountsSerializer(UserBankAccounts.objects.get(id=serializer.data['id'])).data
                return ({"data": res_data, "code": status.HTTP_201_CREATED, "message": "Account added successfully"})

            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})
        return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Account already there."})

    def get_bank_accounts_by_token(self, request, format=None):
        bank_account = UserBankAccounts.objects.filter(user = request.user)
        if bank_account:
            serializer = UserBankAccountsSerializer(bank_account, many=True)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Account Fetched successfully."})
        else:
            bank_account = None
            return ({"data": bank_account, "code": status.HTTP_200_OK, "message": "Account Fetched successfully."})
    
    def update_bank_accounts_by_token(self, request, id, format=None):
        bank_obj = UserBankAccounts.objects.filter(id = id, user = request.user.id).exists
        if bank_obj:
            rest_acnts = UserBankAccounts.objects.filter(user = request.user.id).update(primary = False)
            primary_acnt = UserBankAccounts.objects.filter(id = id).update(primary = True)
            serializer = UserBankAccountsSerializer(primary_acnt, many=True)
            return ({"data": [], "code": status.HTTP_200_OK, "message": "Account Updated successfully."})
        else:
            return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Account not found."})