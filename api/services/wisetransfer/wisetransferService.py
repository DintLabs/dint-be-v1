from dint import settings
from api.models import WiseRecepients, WiseQuotes, WisePayments
from api.serializers.wisetransfer import WiseQuotesSerializer, WiseRecepientsSerializer, WisePaymentsSerializer
from api.utils.messages.userMessages import *
from .wisetransferBaseService import WiseTransferBaseService

import requests

from api.utils.messages.commonMessages import BAD_REQUEST, RECORD_NOT_FOUND
from rest_framework import status
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from django.template.loader import render_to_string
import string

import json

from datetime import datetime

from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login
from api.models.userModel import User

from django.forms.models import model_to_dict
import uuid

class WiseTransferService(WiseTransferBaseService):
    
    def __init__(self):
        pass
    
    def create_quotes_by_token(self, request, format=None):
        
        url = settings.WISE_URL +'/v2/quotes'
     
        token = settings.WISE_TOKEN
        payload = json.dumps({
        "sourceCurrency": request.data['sourceCurrency'],
        "targetCurrency": request.data['targetCurrency'],
        "sourceAmount": request.data['sourceAmount'],
        "targetAmount" : request.data['targetAmount'],
        "profile" : settings.WISE_PROFILE_ID
        })
        headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
        }
        response = requests.post(url, headers = headers, data = payload)
        final = response.json()
        
        guid = uuid.uuid4()
        user_obj = User.objects.get(id = request.user.id)
        
        quote = WiseQuotes.objects.filter(user = user_obj)
        if len(quote) == 0:
            new_quote_obj = WiseQuotes.objects.create(user = user_obj, sourceCurrency = final['sourceAmount'], targetCurrency = final['targetCurrency'], sourceAmount = final['sourceAmount'], quote_id = final['id'], guid = guid )
        else:
            new_quote = WiseQuotes.objects.filter(user = user_obj).update(user = user_obj, sourceCurrency = final['sourceAmount'], targetCurrency = final['targetCurrency'], sourceAmount = final['sourceAmount'], quote_id = final['id'], guid = guid )
           
            new_quote_obj = WiseQuotes.objects.get(user = user_obj)    
          
        serializer = WiseQuotesSerializer(new_quote_obj, data = request.data)
        
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Quotes Created Successfully"})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})

        
    def get_quotes_by_token(Self, request, format=None):
        quotes = WiseQuotes.objects.filter(user = request.user.id)
       
        if quotes:
            serializer = WiseQuotesSerializer(quotes, many=True)
            data = serializer.data
            return ({"data": data, "code": status.HTTP_200_OK, "message": "User Quotes fetched Successfully"})
        else:
            data = None
            return ({"data": data, "code": status.HTTP_200_OK, "message": "User Quotes fetched Successfully"})

        return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "No data found"})

    
    def create_recipients_by_token(self, request, format=None):
        data = request.data
       
        details = data['details']
        address = details['address']

        url = settings.WISE_URL +'/v1/accounts'
        token = settings.WISE_TOKEN
       
        payload = json.dumps({
        "profile" : settings.WISE_PROFILE_ID,
        "accountHolderName": request.data['accountHolderName'],
        "currency": request.data['currency'],
        "type": request.data['type'],
        "details": {
            "address": {
            "city": address['city'],
            "countryCode": address['countryCode'],
            "postCode": address['postCode'],
            "state": address['state'],
            "firstLine": address['firstLine']
            },
            "legalType" : details['legalType'],
            "abartn": details['abartn'],
            "accountType": details['accountType'],
            "accountNumber": details['accountNumber'],
        }
        })
        headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
        }
        response = requests.post(url, headers = headers, data = payload)
        final = response.json()
        details = final['details']
        address =details['address']

        last_digit = details['accountNumber'][-4:]
        user_id = request.user.id
        user_obj = User.objects.get(id = user_id)
        RecepientAccount = WiseRecepients.objects.create(user = user_obj, accountHolderName = final['accountHolderName'], accountNumber = last_digit, receipt_id = final['id'], abartn = details['abartn'], country = address['countryCode'], city = address['city'], state = address['city'], postCode = address['postCode'], firstLine = address['firstLine'])

        acnt_data = model_to_dict(RecepientAccount)
     
        serializer = WiseRecepientsSerializer(RecepientAccount, data = acnt_data)
        if serializer.is_valid():
            serializer.save()
            
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Recepient Created Successfully"})
        else:
            return ({"data": serializer.error, "code": status.HTTP_200_OK, "message": "Something Went Wrong"})

    def get_recipients_by_token(self, request, format=None):
        receipt_accounts = WiseRecepients.objects.all()
       
        if receipt_accounts:
            serializer = WiseRecepientsSerializer(receipt_accounts, many=True)
            preference = serializer.data
            return ({"data": preference, "code": status.HTTP_200_OK, "message": "Details fetched Successfully"})
        else:
            preference = None
            return ({"data": preference, "code": status.HTTP_200_OK, "message": "Details fetched Successfully"})

        return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "No data found"})

    
    def delete_recipient_account_by_token(self, request, pk, format=None):
        receipt_accounts = WiseRecepients.objects.filter(id = pk)
        if not receipt_accounts.exists():
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": "Account not exists"})
        else:
            receipt_accounts.delete()
            return ({"code": status.HTTP_200_OK, "message": "Account deleted successfully"})

    # def update_recipient_account_by_token(self, request, pk, format=None):
    #     data = i
    #     try:
    #         account_obj = UserRecepientAccount.objects.get(id = pk)
    #     except account_obj.DoesNotExist:
    #         return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
    #     if data['primary'] == 'True':
    #         others = UserBookaccounts.objects.exclude(id = pk).filter(user = request.user).update( primary = False)
    #     serializer = UserBankaccountsSerializer(bankaccount_obj, data=data)
    #     if serializer.is_valid ():
    #         serializer.save ()
    #         return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Updated"})
    #     else:
    #         return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

   
    def create_wise_transfer_by_token(self, request, format=None):

        data = request.data
        details = data['details']
      
        transferPurpose = details['transferPurpose']
        url = settings.WISE_URL +'/v1/transfers'
        token = settings.WISE_TOKEN

        payload = json.dumps({
        "targetAccount" : request.data['targetAccount'],
        "quoteUuid": request.data['quoteUuid'],
        "customerTransactionId": request.data['customerTransactionId'],
        "details": {
            "reference" : details['reference'],
            "transferPurpose": transferPurpose
        }
        })
        headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
        }
        response = requests.post(url, headers = headers, data = payload)
        final = response.json()
        print(final)
        details = final['details']
        
        user_obj = User.objects.get(id = request.user.id)
        transaction_id = WiseQuotes.objects.get(user = user_obj)
        tranfer_data = model_to_dict(transaction_id)
        transaction_id = tranfer_data['guid']
        
        
        new_transfer = WisePayments.objects.create(transfer_id = final['id'], user = user_obj, profile_id = settings.WISE_PROFILE_ID, quote_uuid = final['quoteUuid'], customerTransactionId = transaction_id, receipt_id = final['targetAccount'], transferPurpose = transferPurpose)

        data = model_to_dict(new_transfer)
        serializer = WisePaymentsSerializer(new_transfer, data = data)
        if serializer.is_valid():
            serializer.save()
            transfer_id = final['id'] 
            request.session['transfer_id'] = transfer_id
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Transfer Created Successfully"})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def create_wise_payment_by_token(self, request, format=None):
        data = request.data
      
        transfer_id = request.session.get('transfer_id')

        url = settings.WISE_URL +'/v3/profiles/'+settings.WISE_PROFILE_ID+'/transfers/'+str(transfer_id)+'/payments'
        token = settings.WISE_TOKEN

        payload = json.dumps({
        "type" : data['type']
        
        })
        headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
        }

        response = requests.post(url, headers = headers, data = payload)
        final = response.json()
        return final
    