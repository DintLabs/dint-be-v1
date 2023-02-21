from __future__ import print_function
from cryptography.fernet import Fernet
from dint import settings
from api.serializers.user import (UserLoginDetailSerializer, UserCreateUpdateSerializer,
                                  UserCloseFriendsSerializer, UserStatusUpdateSerializer, UserIdentitySerializer)
from api.models.userFollowersModel import UserFollowers
from api.models import User, UserSession, UserReferralWallet, UserPreferences, UserBookmarks, Posts, UserCloseFriends, UserIdentity
from api.utils.messages.userMessages import *
from .userBaseService import UserBaseService
from django.core.files.base import ContentFile
from curses.ascii import US
from multiprocessing import managers
import re
import requests
from api.serializers.user.userSerializer import GetUserPageProfileSerializer, GetUserProfileSerializer, UpdateUserProfileSerializer, UpdateUserWalletSerializer, GetUserPreferencesSerializer, UpdateUserPreferencesUpdateSerializer, GetUserBookmarksSerializer, CreateUserBookmarksSerializer, ProfileByUsernameSerializer
from api.utils.messages.commonMessages import BAD_REQUEST, RECORD_NOT_FOUND
from rest_framework import status
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from django.template.loader import render_to_string
import string
# from twilio.rest import Client
import json
import base64
import random
# import datetime
from django.core.mail import send_mail
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login
from django.db.models import Q
import pytz
from datetime import datetime, timedelta
import jwt
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
from django.forms.models import model_to_dict
from web3 import Web3
from web3.middleware import geth_poa_middleware
from dotenv import load_dotenv
from eth_account import Account
import secrets
from binascii import hexlify
load_dotenv()
import idanalyzer
from dint import settings
import os
from PIL import Image
from base64 import b64encode
from api.services.uploadMedia import uploadMediaService
from api.utils.saveImage import saveImage
from django.forms.models import model_to_dict
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from itertools import chain
from api.utils.token import account_activation_token

class UserService(UserBaseService):
    """
    Allow any user (authenticated or not) to access this url 
    """

    def __init__(self):
        pass

    def login(self, request, format=None):

        validated_data = self.validate_auth_data(request)
        username = request.data['email']
        fire_base_auth_key = request.data['fire_base_auth_key']
        username = username.lower()

        user = self.user_authenticate(username, fire_base_auth_key)
    
        if user is not None:
            login(request, user)
            serializer = UserLoginDetailSerializer(user)
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY)
            user_details = serializer.data
            user_details['token'] = token
            # User.objects.filter(pk=user.pk).update(auth_token=token)
            user_session = self.create_update_user_session(
                user, token, request)
            user.is_online = True
            user.save()
            user_obj = User.objects.get(email = username)
            referral = UserReferralWallet.objects.filter(user_referral = user_obj)
            if referral:
                return ({"data": user_details, "code": status.HTTP_200_OK, "message": "LOGIN_SUCCESSFULLY"})
            else:
                return ({"data": user_details, "code": status.HTTP_200_OK, "message": "User don't have referral code"})
        return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "INVALID_CREDENTIALS"})

    def user_authenticate(self, user_name, fire_base_auth_key):
        try:
            user = User.objects.get(email=user_name)
            if user.fire_base_auth_key == fire_base_auth_key:
                return user  # return user on valid credentials
        except User.DoesNotExist:
            return None

    def validate_auth_data(self, request):
        error = {}
        if not request.data.get('email'):
            error.update({'email': "FIELD_REQUIRED"})

        if request.headers.get('device-type') == 'android' or request.headers.get('device-type') == 'ios':
            if not request.data.get('device_id'):
                error.update({'device_id': "FIELD_REQUIRED"})

        if error:
            raise ValidationError(error)

    def create_update_user_session(self, user, token, request):
        """
        Create User Session
        """
        print(request.headers.get('device-type'))
        print(request.data.get('device_id'))

        user_session = self.get_user_session_object(
            user.pk, request.headers.get('device-type'), request.data.get('device_id'))

        if user_session is None:
            UserSession.objects.create(
                user=user,
                token=token,
                device_id=request.data.get('device_id'),
                device_type=request.headers.get('device-type'),
                app_version=request.headers.get('app-version')
            )

        else:
            user_session.token = token
            user_session.app_version = request.headers.get('app-version')
            user_session.save()

        return user_session

    def get_user_session_object(self, user_id, device_type, device_id=None):
        try:
            if device_id:
                try:
                    return UserSession.objects.get(user=user_id, device_type=device_type, device_id=device_id)
                except UserSession.DoesNotExist:
                    return None

            return UserSession.objects.get(user=user_id, device_type=device_type, device_id=device_id)

        except UserSession.DoesNotExist:
            return None

    def sign_up(self, request, format=None):
        request.data['referral_id'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        if 'referred_by' in request.data:
            try:
                User.objects.get(referral_id=request.data['referred_by'])
            except User.DoesNotExist:
                return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Provided Referral ID is not correct!"})
        serializer = UserCreateUpdateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = User.objects.get(id=serializer.data.get('id'))
            user.is_active = True
            user.is_online = True
            user.save()
            referral_address = '0x0000000000000000000000000000000000000000'
            if request.data.get('referred_by', None):
                user_referred_by = User.objects.get(referral_id=request.data['referred_by'])
                user_referral_wallet = UserReferralWallet(referred_by=user_referred_by)
                user_referral_wallet.user_referral = user
                user_referral_wallet.save()
                referral_user = User.objects.get(email = user_referred_by)
                encrypted_address = referral_user.wallet_address
                wallet_bytes = bytes(encrypted_address)
                key = Fernet(settings.ENCRYPTION_KEY)
                referral_decwallet = key.decrypt(wallet_bytes).decode()
                referral_address = referral_decwallet
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY)
            user_details = serializer.data
            user_details['token'] = token
            user_details['is_online'] = True
            priv = secrets.token_hex(32)
            wallet_private_key = "0x" + priv
            acct = Account.from_key(wallet_private_key)
            wallet_address = acct.address
            address = wallet_address
            key = Fernet(settings.ENCRYPTION_KEY)
            encrypted_wallet_address = key.encrypt(address.encode())
            encrypted_wallet_privatekey = key.encrypt(wallet_private_key.encode())
            user.wallet_address = encrypted_wallet_address
            user.wallet_private_key = encrypted_wallet_privatekey
            user.save()
            user_details['wallet_address'] = encrypted_wallet_address
            node_url = settings.NODE_URL
            web3 = Web3(Web3.HTTPProvider(node_url))
            web3.middleware_onion.inject(geth_poa_middleware, layer=0)
            address = Web3.toChecksumAddress(settings.DINT_TOKEN_DISTRIBUTOR_ADDRESS)
            private_key= settings.OWNER_PRIVATE_KEY
            new_user = acct.address
            abi = json.loads('[{"inputs":[{"internalType":"address","name":"_dintToken","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_recipient","type":"address"},{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"_id","type":"uint256"}],"name":"rewardSent","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"_sender","type":"address"},{"indexed":false,"internalType":"address","name":"_recipient","type":"address"},{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"tipSent","type":"event"},{"inputs":[{"internalType":"address","name":"_referrer","type":"address"},{"internalType":"bool","name":"_blocked","type":"bool"}],"name":"blockUnblockReferrer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"bool","name":"_isManaged","type":"bool"}],"name":"changeManagedState","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_referrer","type":"address"},{"internalType":"bool","name":"_isReferrer","type":"bool"}],"name":"changeReferrerState","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"dintToken","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"feeCollector","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"isRewardSent","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"maxDuration","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"address","name":"_referrer","type":"address"}],"name":"register","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"uint256","name":"_postId","type":"uint256"}],"name":"reward","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_sender","type":"address"},{"internalType":"address","name":"_recipient","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"sendDint","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_feeCollector","type":"address"}],"name":"setFeeCollector","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint64","name":"_durationInSeconds","type":"uint64"}],"name":"setMaxDuration","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"}],"name":"unRegister","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"user","outputs":[{"internalType":"bool","name":"isRegistered","type":"bool"},{"internalType":"bool","name":"isManaged","type":"bool"},{"internalType":"bool","name":"isReferrer","type":"bool"},{"internalType":"bool","name":"blockedReferrer","type":"bool"},{"internalType":"uint64","name":"startedReferringAt","type":"uint64"},{"internalType":"address","name":"tipReceiverToReferrer","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_token","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"address","name":"_to","type":"address"}],"name":"withdrawToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]') 

            contract = web3.eth.contract(address = address , abi = abi)
            user_address = contract.functions.owner().call()
            nonce = web3.eth.getTransactionCount(user_address) 
            register = contract.functions.register(new_user, referral_address).buildTransaction({  
                'from': user_address,
                'chainId': 80001,   
                'gasPrice': web3.toWei('30', 'gwei'),  
                'nonce': nonce,  
            })  
            signed_txn = web3.eth.account.signTransaction(register, private_key)  
            result = web3.eth.sendRawTransaction(signed_txn.rawTransaction)   
            tx_receipt = web3.eth.wait_for_transaction_receipt(result)  
            try:
                user = User.objects.get(id = serializer.data.get('id'))
                pk = user.id
                print(pk)
                sending_verification_email = self.send_verification_email_by_token(request, pk)
                return ({"data": user_details, "code": status.HTTP_201_CREATED, "message": "User Created Successfully and email sent successfully for the verification"})
            except:
                return ({"data": user_details, "code": status.HTTP_201_CREATED, "message": "User Created Successfully"})
        # if not valid
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})
    
    def withdraw_dint_token(self, request, format=None):
        url = settings.WITHDRAW_DINT_TOKEN_URL
        payload = json.dumps({
        "user_id" : request.data['user_id'],
        "amount" : request.data['amount']
        })
        headers = {
        'Content-Type': 'application/json',
        'apikey':settings.NODE_API_KEY
        }
        try:
            response = requests.post(url, headers = headers, data = payload)
            data = response.json()
            Hash = data['hash']
            node_url = settings.NODE_URL
            web3 = Web3(Web3.HTTPProvider(node_url))
            dintReciept = web3.eth.wait_for_transaction_receipt(Hash)  
            if (dintReciept.status == 1):
                return ({"data": data, "code": status.HTTP_201_CREATED, "message": "Token sent successfully"})
            else:
                return ({"data": data, "code": status.HTTP_400_BAD_REQUEST, "message": "Transaction Failed"})
        except:
            return ({"data": data, "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})

    def send_dint_token(self, request, format=None):
        url = settings.SEND_DINT_TOKEN_URL
        requested_data = request.data
        payload = json.dumps({
        "sender_id" : request.data['sender_id'],
        "reciever_id" : request.data['reciever_id'],
        "amount" : request.data['amount']
        })
        headers = {
        'Content-Type': 'application/json',
        'apikey':settings.NODE_API_KEY
        }
        try:
            response = requests.post(url, headers = headers, data = payload)
            data = response.json()
            Hash = data['Hash']
            node_url = settings.NODE_URL
            web3 = Web3(Web3.HTTPProvider(node_url))
            dintReciept = web3.eth.wait_for_transaction_receipt(Hash)  
            if (dintReciept.status == 1):
                return ({"data": data, "code": status.HTTP_201_CREATED, "message": "Token sent successfully"})
            else:
                return ({"data": data, "code": status.HTTP_400_BAD_REQUEST, "message": "Transaction Failed"})
        except:
             return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})
        
    def send_reward_by_token(self, request, format=None):
        receiver = User.objects.get(id = request.user.id)
        receiver_wallet = receiver.wallet_address

        receiver_wallet_bytes = bytes(receiver_wallet)
        key = Fernet(settings.ENCRYPTION_KEY)
        receiver_decwallet = key.decrypt(receiver_wallet_bytes).decode()
        print(receiver_decwallet)

        sender_obj = User.objects.get(id = request.user.id)
        sender_wallet = sender_obj.wallet_address
        # sender_wallet_key = sender_obj.wallet_private_key
        print(sender_wallet)
        node_url = settings.NODE_URL
        web3 = Web3(Web3.HTTPProvider(node_url))
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        address = Web3.toChecksumAddress(settings.ADDRESS)
        private_key = settings.OWNER_PRIVATE_KEY

        abi = json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"_sender","type":"address"},{"indexed":false,"internalType":"address","name":"_recipient","type":"address"}],"name":"tipSent","type":"event"},{"inputs":[{"internalType":"address","name":"_referrer","type":"address"},{"internalType":"bool","name":"_blocked","type":"bool"}],"name":"blockUnblockReferrer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"blockedReferrer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"bool","name":"_isManaged","type":"bool"}],"name":"changeManagedState","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bool","name":"_isReferrer","type":"bool"}],"name":"changeReferrerState","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"dintToken","outputs":[{"internalType":"contract IERC20","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"feeCollector","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isManaged","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isReferrer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isRegistered","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"address","name":"_referrer","type":"address"},{"internalType":"bool","name":"_isManaged","type":"bool"}],"name":"register","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"reward","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_recipient","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"sendDint","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_feeCollector","type":"address"}],"name":"setFeeCollector","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"startedReferringAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"tipRecieverToReferrer","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"}],"name":"unRegister","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_token","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"address","name":"_to","type":"address"}],"name":"withdrawToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]') 
        contract = web3.eth.contract(address = address , abi = abi)

        dintAdd =  Web3.toChecksumAddress(settings.DINT_TOKEN_ADDRESS)
        dintABI = json.loads('[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_amount","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"creationBlock","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_newController","type":"address"}],"name":"changeController","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_blockNumber","type":"uint256"}],"name":"balanceOfAt","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"version","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_cloneTokenName","type":"string"},{"name":"_cloneDecimalUnits","type":"uint8"},{"name":"_cloneTokenSymbol","type":"string"},{"name":"_snapshotBlock","type":"uint256"},{"name":"_transfersEnabled","type":"bool"}],"name":"createCloneToken","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"parentToken","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_owner","type":"address"},{"name":"_amount","type":"uint256"}],"name":"generateTokens","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_blockNumber","type":"uint256"}],"name":"totalSupplyAt","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"transfersEnabled","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"parentSnapShotBlock","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_amount","type":"uint256"},{"name":"_extraData","type":"bytes"}],"name":"approveAndCall","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_owner","type":"address"},{"name":"_amount","type":"uint256"}],"name":"destroyTokens","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_token","type":"address"}],"name":"claimTokens","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"tokenFactory","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_transfersEnabled","type":"bool"}],"name":"enableTransfers","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"controller","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[{"name":"_tokenFactory","type":"address"},{"name":"_parentToken","type":"address"},{"name":"_parentSnapShotBlock","type":"uint256"},{"name":"_tokenName","type":"string"},{"name":"_decimalUnits","type":"uint8"},{"name":"_tokenSymbol","type":"string"},{"name":"_transfersEnabled","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_token","type":"address"},{"indexed":true,"name":"_controller","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"}],"name":"ClaimedTokens","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_cloneToken","type":"address"},{"indexed":false,"name":"_snapshotBlock","type":"uint256"}],"name":"NewCloneToken","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_spender","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"}],"name":"Approval","type":"event"}]')

        dintCont = web3.eth.contract(address = dintAdd , abi = dintABI)

        user_address = contract.functions.owner().call()
        user_ref = '0x0000000000000000000000000000000000000000'
        receiver_add = receiver_decwallet
        owner = contract.functions.owner().call()
        nonce = web3.eth.getTransactionCount(owner)  
        tip_dint = 10

        balance = dintCont.functions.balanceOf(address).call()
        print(balance, "Available Dint")

        new_nonce = web3.eth.getTransactionCount(owner)  

        print("Rewarding...")

        sendReward = contract.functions.reward(receiver_add, tip_dint).buildTransaction({
            'from': user_address,
            'chainId': 80001,  
            'gasPrice': web3.toWei('30', 'gwei'),  
            'nonce': new_nonce,     
        })

        singed_reward_txn = web3.eth.account.signTransaction(sendReward, private_key)

        reward_result = web3.eth.sendRawTransaction(singed_reward_txn.rawTransaction)

        reward_reciept = web3.eth.wait_for_transaction_receipt(reward_result)

        print("Transaction Hash:", reward_reciept.transactionHash.hex())

        balance = dintCont.functions.balanceOf(receiver_add).call()
        print(balance, "Available Dint")

    def send_otp(self, user):
        try:
            tz = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(tz)

            # user = self.get_object_by_email (email)
            otp = random.randint(100000, 999999)
            body_msg = 'Your OTP is {} . OTP is valid for 1 hour or 1 successfull attempt.'.format(
                otp)
            account_sid = "XXXXXXXXXXXXXXXXXXXXXXX"
            auth_token = "XXXXXXXXXXXXXXXXXXXXXXXXXXX"
            # client = Client(account_sid, auth_token)
            # message = client.messages.create(
            #         to="+91{}".format("8146664616"),
            #         from_="+18152013322",
            #         body=body_msg)

            user.otp = 123485
            user.otp_send_time = current_time
            user.save()

        except Exception as e:
            raise ValidationError(e)

    def send_otp_for_old_user(self, request, format=None):
        try:
            tz = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(tz)
            try:
                user = User.objects.get(phone_no=request.data.get('phone_no'))
            except User.DoesNotExist:
                raise ValidationError({"error": "Please Enter valid phone_no"})

            otp = random.randint(100000, 999999)
            body_msg = 'Your OTP is {} . OTP is valid for 1 hour or 1 successfull attempt.'.format(
                otp)
            account_sid = "XXXXXXXXXXXXXXXXXXXXXXX"
            auth_token = "XXXXXXXXXXXXXXXXXXXXXXXXXXX"
            client = Client(account_sid, auth_token)
            message = client.messages.create(
                to="+91{}".format("8146664616"),
                from_="+18152013322",
                body=body_msg)

            user.otp = otp
            user.otp_send_time = current_time
            user.save()

        except Exception as e:
            raise ValidationError(e)

        return ({"data": None, "code": status.HTTP_200_OK, "message": "OTP Sent Successfully"})

    def verify_otp(self, request, format=None):
        # self.validate_otp_data (request.data)
        tz = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(tz)
        now_date = current_time.strftime('%m/%d/%y')
        now_time = current_time.strftime('%H:%M')

        id = request.data['id']
        otp = request.data['otp']

        try:
            user = User.objects.get(id=id)
        except User.DoesNotExist:
            user = None

        if user:
            if user.otp_varification is False:
                if int(user.otp) == int(otp):
                    otp_send_time = user.otp_send_time
                    otp_send_time = otp_send_time.astimezone(
                        tz) + timedelta(hours=1)

                    otp_date = datetime.strftime(otp_send_time, '%m/%d/%y')
                    otp_time = datetime.strftime(otp_send_time, '%H:%M')

                    if now_date == otp_date and now_time <= otp_time:
                        user.otp_varification = True
                        user.save()
                        return {"data": None, "code": status.HTTP_200_OK, "message": OTP_VERIFID}
                    else:
                        return {"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": OTP_EXPIRED}
                else:
                    return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": WRONG_OTP})
            else:
                return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": NUMBER_ALREADY_VARIFIED})

        else:
            return {"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": DETAILS_INCORRECT}

    def get_profile_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        context = {"profile_user_id": user_obj.id,
                   "logged_in_user": request.user.id}
        serializer = GetUserProfileSerializer(user_obj, context=context)
        # payload = jwt_payload_handler(user_obj)
        # token = jwt.encode(payload, settings.SECRET_KEY)
        user_details = serializer.data
        # user_details['wallet_token'] = user_obj.wallet_token
        return ({"data": user_details, "code": status.HTTP_200_OK, "message": "User Profile fetched Successfully"})

    def get_page_profile_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        context = {"profile_user_id": user_obj.id,
                   "logged_in_user": request.user.id}
        serializer = GetUserPageProfileSerializer(user_obj, context=context)
        payload = jwt_payload_handler(user_obj)
        token = jwt.encode(payload, settings.SECRET_KEY)
        user_details = serializer.data
        user_details['token'] = token
        return ({"data": user_details, "code": status.HTTP_200_OK, "message": "User Profile fetched Successfully"})

    def update_profile_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        serializer = UpdateUserProfileSerializer(user_obj, data=request.data)
        try:
            new_email = request.data['email']
            email_exists = User.objects.filter(email=new_email)
            if serializer.is_valid():
                if not email_exists:
                    serializer.save()
                    return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Profile Updated Successfully"})
                else:
                    return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Email already exists"})
        except KeyError:
            pass
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Profile Updated Successfully"})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def get_wallet_by_token(self, request, format=None):
        user_obj = User.objects.filter(id = request.user.id)
        user = User.objects.get(id = request.user.id)
        wallet = user.wallet_address
        wallet_address = wallet.tobytes()
        key = Fernet(settings.ENCRYPTION_KEY)
        user_decwallet = key.decrypt(wallet_address).decode()
        node_url = settings.NODE_URL
        web3 = Web3(Web3.HTTPProvider(node_url))
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        address = settings.DINT_TOKEN_DISTRIBUTOR_ADDRESS
        checksum_address = Web3.toChecksumAddress(address)
        user_address = user_decwallet

        abi = json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"_sender","type":"address"},{"indexed":false,"internalType":"address","name":"_recipient","type":"address"}],"name":"tipSent","type":"event"},{"inputs":[{"internalType":"address","name":"_referrer","type":"address"},{"internalType":"bool","name":"_blocked","type":"bool"}],"name":"blockUnblockReferrer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"blockedReferrer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"bool","name":"_isManaged","type":"bool"}],"name":"changeManagedState","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bool","name":"_isReferrer","type":"bool"}],"name":"changeReferrerState","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"dintToken","outputs":[{"internalType":"contract IERC20","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"feeCollector","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isManaged","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isReferrer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isRegistered","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"address","name":"_referrer","type":"address"},{"internalType":"bool","name":"_isManaged","type":"bool"}],"name":"register","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"reward","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_recipient","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"sendDint","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_feeCollector","type":"address"}],"name":"setFeeCollector","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"startedReferringAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"tipRecieverToReferrer","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"}],"name":"unRegister","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_token","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"address","name":"_to","type":"address"}],"name":"withdrawToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]') 
        contract = web3.eth.contract(address = checksum_address , abi = abi)
        dintAddress = settings.DINT_TOKEN_ADDRESS
        checksum_dintAddress = Web3.toChecksumAddress(dintAddress)
        dintABI = json.loads('[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_amount","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"creationBlock","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_newController","type":"address"}],"name":"changeController","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_blockNumber","type":"uint256"}],"name":"balanceOfAt","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"version","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_cloneTokenName","type":"string"},{"name":"_cloneDecimalUnits","type":"uint8"},{"name":"_cloneTokenSymbol","type":"string"},{"name":"_snapshotBlock","type":"uint256"},{"name":"_transfersEnabled","type":"bool"}],"name":"createCloneToken","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"parentToken","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_owner","type":"address"},{"name":"_amount","type":"uint256"}],"name":"generateTokens","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_blockNumber","type":"uint256"}],"name":"totalSupplyAt","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"transfersEnabled","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"parentSnapShotBlock","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_amount","type":"uint256"},{"name":"_extraData","type":"bytes"}],"name":"approveAndCall","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_owner","type":"address"},{"name":"_amount","type":"uint256"}],"name":"destroyTokens","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_token","type":"address"}],"name":"claimTokens","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"tokenFactory","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_transfersEnabled","type":"bool"}],"name":"enableTransfers","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"controller","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[{"name":"_tokenFactory","type":"address"},{"name":"_parentToken","type":"address"},{"name":"_parentSnapShotBlock","type":"uint256"},{"name":"_tokenName","type":"string"},{"name":"_decimalUnits","type":"uint8"},{"name":"_tokenSymbol","type":"string"},{"name":"_transfersEnabled","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_token","type":"address"},{"indexed":true,"name":"_controller","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"}],"name":"ClaimedTokens","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_cloneToken","type":"address"},{"indexed":false,"name":"_snapshotBlock","type":"uint256"}],"name":"NewCloneToken","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_spender","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"}],"name":"Approval","type":"event"}]')
        dintCont = web3.eth.contract(address = checksum_dintAddress , abi = dintABI)
        balance = dintCont.functions.balanceOf(user_address).call()
        balance = web3.fromWei(balance, 'ether')
        return ({"data": {'wallet_balance': balance, 'wallet_address': user_address}, "code": status.HTTP_200_OK, "message": "User Wallet fetched Successfully"})

    def update_wallet_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        serializer = UpdateUserWalletSerializer(user_obj, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Wallet saved Successfully"})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def encrypted_wallet_token(self):
        random_token = ''.join(random.choices(
            string.ascii_uppercase + string.digits, k=20))
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        encrypted_text = cipher_suite.encrypt(random_token.encode('ascii'))
        encrypted_text = base64.urlsafe_b64encode(
            encrypted_text).decode("ascii")
        return encrypted_text

    def decrypt_wallet_token_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        encrypted_wallet_token = base64.urlsafe_b64decode(
            user_obj.wallet_token)
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        decoded_text = cipher_suite.decrypt(
            encrypted_wallet_token).decode("ascii")
        response_data = {}
        response_data['token'] = decoded_text
        return ({"data": response_data, "code": status.HTTP_200_OK, "message": "Wallet token decrypted Successfully"})

    def get_bookmarks_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        if user_obj:
            try:
                if request.GET.get('type') is None:
                    user_bookmarks = UserBookmarks.objects.filter(
                        user=user_obj).all()

                else:
                    user_bookmarks = UserBookmarks.objects.filter(
                        user=user_obj, post__type=request.GET['type']).all()

                if user_bookmarks:
                    latest_user_bookmarks = user_bookmarks.order_by(
                        '-created_at')
                    context = {"profile_user_id": user_obj.id,
                               "logged_in_user": request.user.id}
                    serializer = GetUserBookmarksSerializer(
                        latest_user_bookmarks, many=True, context=context)
                    preference = serializer.data
                else:
                    preference = None
            except UserPreferences.DoesNotExist:
                preference = None
            return ({"data": preference, "code": status.HTTP_200_OK, "message": "User Bookmarks fetched Successfully"})
        return ({"data": [{error: 'User not found'}], "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def create_bookmark_by_token(self, request, format=None):
        post_exist = UserBookmarks.objects.filter(
            user=request.user, post=request.data['post']).exists()
        if not post_exist:
            serializer = CreateUserBookmarksSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                res_data = GetUserBookmarksSerializer(
                    UserBookmarks.objects.get(id=serializer.data['id'])).data
                return ({"data": res_data, "code": status.HTTP_201_CREATED, "message": "Bookmark created successfully"})
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})
        return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Bookmark already there."})

    def delete_bookmark_by_token(self, request, pk, format=None):
        post_exist = UserBookmarks.objects.filter(user=request.user, post=pk)
        if not post_exist.exists():
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": "Bookmark not exists"})
        else:
            post_exist.delete()
            return ({"code": status.HTTP_200_OK, "message": "Bookmark deleted successfully"})

    def get_preferences_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        if user_obj:
            try:
                user_preferences_obj = UserPreferences.objects.get(
                    user=user_obj)
                context = {"profile_user_id": user_obj.id, "logged_in_user": request.user.id,
                           "preference_id": user_preferences_obj.id}
                serializer = GetUserPreferencesSerializer(
                    user_preferences_obj, context=context)
                preference = serializer.data
            except UserPreferences.DoesNotExist:
                preference = None
            return ({"data": preference, "code": status.HTTP_200_OK, "message": "User Preferences fetched Successfully"})
        return ({"data": [{error: 'User not found'}], "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def update_preferences_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        if user_obj:
            try:
                user_preferences_obj = UserPreferences.objects.get(
                    user=user_obj)
            except UserPreferences.DoesNotExist:
                user_preferences_obj = UserPreferences.objects.create(
                    user=user_obj)

            serializer = UpdateUserPreferencesUpdateSerializer(
                user_preferences_obj, data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Preferences saved Successfully"})
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
        return ({"data": [{error: 'User not found'}], "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def get_profile_by_username(self, request, format=None):
        try:
            user_obj = User.objects.get(
                custom_username=request.data['custom_username'])
            if (user_obj.is_private == False):
                context = {"profile_user_id": user_obj.id,
                           "logged_in_user": request.user.id}
                serializer = GetUserProfileSerializer(
                    user_obj, context=context)
                return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Profile fetched Successfully"})
            else:
                try:
                    is_followed = UserFollowers.objects.filter(
                        user=user_obj, follower=request.user.id, request_status=True)
                    if is_followed.exists():
                        context = {"profile_user_id": user_obj.id,
                                   "logged_in_user": request.user.id}
                        serializer = GetUserProfileSerializer(
                            user_obj, context=context)
                        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User Profile fetched Successfully"})
                except:
                    pass

        except User.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        context = {"profile_user_id": user_obj.id,
                   "logged_in_user": request.user.id}
        serializer = ProfileByUsernameSerializer(user_obj, context=context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Follow user to see all the posts"})

    def logout(self, request, format=None):

        # validated_data = self.validate_logout_data(request)
        try:
            jwt_token_str = request.META['HTTP_AUTHORIZATION']
            jwt_token = jwt_token_str.replace('Bearer', '')
            user_detail = jwt.decode(jwt_token, None, None)
            user = User.objects.get(pk=user_detail['user_id'])

            user_session_instance = self.get_user_session_object(
                user.pk, request.headers.get('device-type'), request.data.get('device_id'))

            if user_session_instance:
                user.is_online = False
                user.last_login = datetime.now()
                user.save()
                user_session = self.create_update_user_session(
                    user, None, request)
                return ({"data": None, "code": status.HTTP_200_OK, "message": "LOGOUT_SUCCESSFULLY"})
            else:
                return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "RECORD_NOT_FOUND"})

        except User.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "RECORD_NOT_FOUND"})

    def get_referred_users_list(self, request, pk, format=None):
        usr_obj = User.objects.filter(referred_by=pk)
        serializer = UserLoginDetailSerializer(usr_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Data Fetched Successfully."})

    def search_any_user(self, request, format=None):
        search_text = request.GET.get('search')
        if search_text is None:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Please provide Search Text"})
        try:
            user = User.objects.filter(able_to_be_found = True).filter(Q(custom_username__icontains=search_text) | Q(display_name__icontains=search_text))
            followers = UserFollowers.objects.filter(follower = request.user.id, request_status = True)
            followers_obj = User.objects.filter(id__in = followers).filter(Q(custom_username__icontains=search_text) | Q(display_name__icontains=search_text))
            result = list(chain(user, followers_obj))
            serializer = UserLoginDetailSerializer(result, many=True)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "OK"})
        except:
            return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Something went wrong"})

    def get_closefriends(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        if user_obj:
            close_friends = UserCloseFriends.objects.filter(
                main_user=user_obj).all()
            if close_friends:
                context = {"profile_user_id": user_obj.id,
                           "logged_in_user": request.user.id}
                serializer = UserCloseFriendsSerializer(
                    close_friends, many=True, context=context)
                close_friends = serializer.data

            else:
                close_friends = None
            return ({"data": close_friends, "code": status.HTTP_200_OK, "message": "User Closefriends fetched Successfully"})
        return ({"data": [{error: 'User not found'}], "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def create_closefriends(self, request, format=None):
        main_user = request.data['main_user']
        close_friend = request.data['close_friend']
        print(request.data)
        friend_exist = UserCloseFriends.objects.filter(
            main_user=main_user, close_friend=close_friend).exists()
        if not friend_exist:
            main_user_obj = User.objects.get(id=main_user)
            close_friend_obj = User.objects.get(id=close_friend)
            create_close_friend = UserCloseFriends.objects.create(
                main_user=main_user_obj, close_friend=close_friend_obj)
            serializer = UserCloseFriendsSerializer(
                create_close_friend, data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                res_data = UserCloseFriendsSerializer(UserCloseFriends.objects.get(id=serializer.data['id'])).data
                return ({"data": res_data, "code": status.HTTP_201_CREATED, "message": "Close friend created successfully"})
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})
        return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Close friend alrerady there."})

    def delete_closefriends(self, request, pk, format=None):
        post_exist = UserCloseFriends.objects.filter(main_user=request.user, close_friend=pk)
        if not post_exist.exists():
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": "Close friend not exists"})
        else:
            post_exist.delete()
            return ({"code": status.HTTP_200_OK, "message": "User remover from close friend  successfully"})

    def update_user_status_by_token(self, request, format=None):
        user_obj = User.objects.get(id=request.user.id)
        serializer = UserStatusUpdateSerializer(user_obj, data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "User status saved Successfully"})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def validate_user_referral(self, request, format=None):
        referred_code = request.data['referred_code']
        try:
            is_valid =  User.objects.get(referral_id=request.data['referred_code'])
            if is_valid:
                return ({"data": [], "code": status.HTTP_200_OK, "message": "code validated"})
        except User.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Provided Referral ID is not correct!"})

    def add_user_referral(self, request, format=None):
        user = request.data['email']
        referral_code = request.data['referral_code']
        user_obj = User.objects.get(email = user)
        
        try:
            referred_by = User.objects.get(referral_id=referral_code)
            if referred_by:
                already_exists = UserReferralWallet.objects.filter(referred_by=referred_by, user_referral = user_obj)
                if not already_exists:
                    user_referral_wallet = UserReferralWallet(referred_by=referred_by, user_referral = user_obj)
                    user_referral_wallet.save()
                    return ({"data": [], "code": status.HTTP_200_OK, "message": "Referral code added"})
                else:
                    return ({"data": [], "code": status.HTTP_200_OK, "message": "Already added"})
        except Exception as e:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Provided Referral ID is not correct!"})

    def user_referral_code_by_token(self, request, format=None):
        user = request.user
        already_exists = UserReferralWallet.objects.filter(user_referral = user)
        if not already_exists:
            return ({"data": [], "code": status.HTTP_405_METHOD_NOT_ALLOWED , "message": "user do not have referral code"})
        else:
            return ({"data": [], "code": status.HTTP_200_OK, "message": "User already have referral code"})
        
    def verify_identity(self, request, format=None):
        face_image = request.data['face_image']
    
        with open("imageToSave.jpeg", "wb") as fh:
            fh.write(base64.b64decode(face_image))

        folder = "IDS"
        document_url=''
        try:
            image_url, image_name = saveImage(request.data['document'], folder)
            document_url = image_url
            # for im in dict((request.data).lists())['face_image']:
            image_url, image_name = saveImage("imageToSave.jpeg", folder)
            #     # print(image_url)
            #     face_image_url = image_url
        except Exception as e:
            print('exception',  e)
            pass
        id_analyzer_key = settings.ID_ANALYZER_KEY
        coreapi = idanalyzer.CoreAPI(id_analyzer_key, "US") 
        coreapi.throw_api_exception(True)
        coreapi.enable_authentication(True, 'quick')

        response = coreapi.scan(document_primary = document_url, biometric_photo = "imageToSave.jpeg")
        if response.get('result'):
            data_result = response['result']
            print("Hello your name is {} {}".format(data_result['firstName'],data_result['lastName']))
        if response.get('face'):
            face_result = response['face']
            print('res' , face_result)
            if face_result['isIdentical']:
                print("Face verification PASSED!")
            else:
                # return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "face verification failed"})
                print("face verification failed")
            print("Confidence Score: "+face_result['confidence'])
        if response.get('authentication'):
            authentication_result = response['authentication']
            if authentication_result['score'] > 0.5:
                try:
                    already_verified = UserIdentity.objects.get(documentNumber = result['documentNumber'], document_type = result['documentType'])
                    if already_verified:
                        return ({"data": [], "code": status.HTTP_200_OK, "message": "Already verified"})
                    print("already verified")
                except Exception as e:
                    print(e)
                    result = response['result']
                    print("result" , result)
                    user_obj = User.objects.get(id = request.user.id)
                    user_identity = UserIdentity.objects.create(user = user_obj,fullname = result['fullName'], document_type = result['documentType'], documentNumber = result['documentNumber'], nationality = result['nationality_full'], verified = True)
                    user_identity.save()
                    try:
                        dob = result['dob']
                        temp_date = datetime.strptime(dob, "%Y/%m/%d").date()
                        user_identity.date_of_birth = temp_date
                        user_identity.save()
                    except Exception as e:
                        pass
                    try:
                        gender = result['sex']
                        user_identity.gender = gender
                        user_identity.save()
                    except:
                        pass
                    data = model_to_dict(user_identity)
                    serializer = UserIdentitySerializer(user_identity, data=data)
                    if serializer.is_valid():
                        serializer.save(user=request.user)
                        print("serializer data",serializer.data)
                        return ({"data": response, "code": status.HTTP_200_OK, "message": "User verified Successfully"})
            elif authentication_result['score'] > 0.3:
                return ({"data": [response], "code": status.HTTP_400_BAD_REQUEST, "message": "Document looks little suspicious"})
            else:
                return ({"data": [response], "code": status.HTTP_400_BAD_REQUEST, "message": "Document uploaded is fake"})
        
    def track_ip_address(self, request, format = None):
        user_ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if user_ip_address:
            ip = user_ip_address.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        already_exists = User.objects.filter(ip_address = ip)
        if already_exists:
            return ({"data": [], "code": status.HTTP_200_OK, "message": "IP address already exists"})
        else:
            create_address = User.objects.filter(id = request.user.id).update(ip_address = ip)
            return ({"data": ip, "code": status.HTTP_200_OK, "message": "IP address tracked successfully"})
    
    def send_verification_email_by_token(self, request, pk, format=None):
        try:
            user_obj = User.objects.get(id = pk)
            print(user_obj)
            date = datetime.now()
            print(date)
            token = account_activation_token.make_token(user_obj.id)
            save_token = User.objects.filter(id = pk).update(email_token = token, email_token_valid = date)
            first_name = user_obj.email
            email = user_obj.email
            configuration = sib_api_v3_sdk.Configuration()
            configuration.api_key['api-key'] = settings.SENDINBLUE_API
            api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
            subject = "This is the verification email from Dint"
            sender = {"name":"Sendinblue","email":"support@dint.com"}
            to = [{"email": email,"name":first_name}]
            html_content = "<html><body><h3>Hii "+first_name+"</h3><p>click here to verify <span style =color:#1A73E8><a href=https://fedev.dint.com>https://fedev.dint.com/"+token+"</a></span</p></body></html>"
        
            headers = {
                "accept": "application/json",
                "api-key": settings.SENDINBLUE_API
            }
            send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to, headers=headers, html_content=html_content, sender=sender, subject=subject)
            try:
                api_response = api_instance.send_transac_email(send_smtp_email)
                return ({"data": [], "code": status.HTTP_200_OK, "message": "Email sent successfully"})
                print("email sent")
            except ApiException as e:
                print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)
        except Exception as e:
            print(e)
            return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Something went wrong"})
    
    def validate_verification_token(self, request, format=None):
        token = request.data['token']
        user = request.user.id
        tz = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(tz)
        try:
            user_obj = User.objects.get(id = request.user.id)
            user_token = user_obj.email_token
            token_send_time = user_obj.email_token_valid
            token_expire_time = token_send_time.astimezone(tz) + timedelta(minutes=15)
            if token_expire_time <= current_time:
                return ({"data": [], "code": status.HTTP_200_OK, "message": "Token is expired"})
            else:
                user_obj.is_email_verified = True
                user_obj.save()
                return ({"data": [], "code": status.HTTP_200_OK, "message": "Token validated"})  
        except:
             return {"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Something went wrong"}

    def get_suggestions(self, request, format=None):
        user_obj = User.objects.exclude(id = request.user.id).filter(able_to_be_found = True).order_by('?')[:5]
        if user_obj:
            serializer = UserLoginDetailSerializer(user_obj, many=True)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "OK"})
        else:
            user_obj= None
            return ({"data": [], "code": status.HTTP_200_OK, "message": "OK"})

    def get_referral_id_by_token(self, request, format=None):
        user = request.user.id
        user_obj = User.objects.get(id = user)
        if user_obj:
            user_referral_id = user_obj.referral_id
            return ({"data": [user_referral_id], "code": status.HTTP_200_OK, "message": "OK"})
        else:
            return {"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "User not found"}
