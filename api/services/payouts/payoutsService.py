from rest_framework import status
from api.utils.messages.commonMessages import *
from api.models.BankAccountsModel import UserBankAccounts
from api.serializers.bankaccounts import UserBankAccountsSerializer
from api.models.PayoutsModel import Payouts
from api.models.userModel import User
from api.serializers.payouts import UserPayoutsSerializer
from .payoutsBaseService import PayoutsBaseService
from django.core.exceptions import ObjectDoesNotExist

class PayoutsService(PayoutsBaseService):
    """
    Allow any user (authenticated or not) to access this url 
    """
    def __init__(self):
        pass
    
    def request_payouts_by_token(self, request, format=None):
        amount = request.data['amount']
        user_obj = User.objects.get(id = request.user.id)
        print(user_obj)
        try:
            bank_obj = UserBankAccounts.objects.get(user = request.user, primary = True)
        except ObjectDoesNotExist:
            return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "User dont have Bank account added"})
        serializer = UserPayoutsSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid():
            serializer.save(user=request.user)
            details = serializer.data
            details['accountHolderName'] = bank_obj.accountHolderName
            details['accountNumber'] = bank_obj.accountNumber
            details['country'] = bank_obj.country
            details['city'] = bank_obj.city
            details['state'] = bank_obj.state
            details['postCode'] = bank_obj.postCode
            res_data = UserPayoutsSerializer(Payouts.objects.get(id=serializer.data['id'])).data
            payouts_obj = Payouts.objects.filter(id=serializer.data['id']).update(accountHolderName = bank_obj.accountHolderName, accountNumber = bank_obj.accountNumber, country = bank_obj.country, city = bank_obj.city, state = bank_obj.state, postCode = bank_obj.postCode)
            return ({"data": details, "code": status.HTTP_201_CREATED, "message": "Payout requested successfully"})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Something went wrong"})

    def get_all_requested_payouts(self, request, format=None):
        user_obj = request.user.id
        is_superuser = User.objects.filter(id = user_obj, is_superuser = True)
        payouts = Payouts.objects.all()
        if not is_superuser:
            return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Only admin allowed"})
        else:
            serializer = UserPayoutsSerializer(payouts, many=True)
            return ({"data":serializer.data, "code": status.HTTP_200_OK, "message": "Payouts Fetched successfully."})
    
    def get_payouts_by_token(self, request, format=None):
        user_obj = request.user.id
        payouts_obj = Payouts.objects.filter(user = user_obj)
        print(payouts_obj)
        if payouts_obj:
            serializer = UserPayoutsSerializer(payouts_obj, many=True)
            return ({"data":serializer.data, "code": status.HTTP_200_OK, "message": "Payouts Fetched successfully."})
        else:
            payouts_obj = None
            return ({"data":payouts_obj, "code": status.HTTP_200_OK, "message": "Payouts Fetched successfully."})
        