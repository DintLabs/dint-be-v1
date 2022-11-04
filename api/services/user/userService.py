from curses.ascii import US
from multiprocessing import managers
import re
from api.serializers.user.userSerializer import GetUserPageProfileSerializer, GetUserProfileSerializer, UpdateUserProfileSerializer, GetUserWalletSerializer, UpdateUserWalletSerializer, GetUserPreferencesSerializer, UpdateUserPreferencesUpdateSerializer, GetUserBookmarksSerializer, CreateUpdatePostsSerializer
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
from django.core.mail import send_mail
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login

import pytz
from datetime import datetime, timedelta
import jwt
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

from django.core.files.base import ContentFile

from .userBaseService import UserBaseService
from api.utils.messages.userMessages import *
from api.models import User, UserSession, UserReferralWallet, UserPreferences, UserBookmarks,Posts
from api.serializers.user import (UserLoginDetailSerializer,
                                  UserCreateUpdateSerializer)

from dint import settings
from cryptography.fernet import Fernet

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

            user_session = self.create_update_user_session(user, token, request)

            return ({"data": user_details,"code": status.HTTP_200_OK,"message": "LOGIN_SUCCESSFULLY"})
        return ({"data": None,"code": status.HTTP_400_BAD_REQUEST, "message": "INVALID_CREDENTIALS"})

    def user_authenticate(self, user_name, fire_base_auth_key):
        try:
            user = User.objects.get(email=user_name)
            if user.fire_base_auth_key == fire_base_auth_key:
                return user # return user on valid credentials
        except User.DoesNotExist:
            return None

    def validate_auth_data(self, request):
        error = {}
        if not request.data.get('email'):
            error.update({'email' : "FIELD_REQUIRED" })


        if request.headers.get('device-type')=='android'or request.headers.get('device-type')=='ios':
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

        user_session = self.get_user_session_object(user.pk, request.headers.get('device-type'), request.data.get('device_id'))

        if user_session is None:
            UserSession.objects.create(
                user = user,
                token = token,
                device_id = request.data.get('device_id'),
                device_type = request.headers.get('device-type'),
                app_version = request.headers.get('app-version')
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
                User.objects.get(referral_id = request.data['referred_by'])
            except User.DoesNotExist:
                return ({"data":None, "code":status.HTTP_400_BAD_REQUEST, "message":"Provided Referral ID is not correct!"})
        serializer = UserCreateUpdateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = User.objects.get (id=serializer.data.get ('id'))
            user.is_active = True
            wallet_token = self.encrypted_wallet_token()
            user.wallet_token = wallet_token
            user.save()
            if request.data.get('referral_by', None):
                user_referred_by = User.objects.get(referral_id=request.data['referred_by'])
                user_referral_wallet = UserReferralWallet(referred_by=user_referred_by)
                user_referral_wallet.user_referral = user
                user_referral_wallet.save()
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY)

            user_details = serializer.data
            user_details['token'] = token
            user_details['wallet_token'] = wallet_token
            # self.send_otp(user)
            return ({"data":user_details, "code":status.HTTP_201_CREATED, "message":"User Created Successfully"})
        #if not valid
        return ({"data":serializer.errors, "code":status.HTTP_400_BAD_REQUEST, "message":"Oops! Something went wrong."})
    

    def send_otp(self, user):
        try:
            tz = pytz.timezone ('Asia/Kolkata')
            current_time = datetime.now (tz)

            # user = self.get_object_by_email (email)
            otp = random.randint (100000, 999999)
            body_msg = 'Your OTP is {} . OTP is valid for 1 hour or 1 successfull attempt.'.format (
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
            user.save ()

            
        except Exception as e:
            raise ValidationError(e)
    
    def send_otp_for_old_user(self, request, format=None):
        try:
            tz = pytz.timezone ('Asia/Kolkata')
            current_time = datetime.now (tz)
            try:
                user = User.objects.get(phone_no=request.data.get('phone_no'))
            except User.DoesNotExist:
                raise ValidationError({"error":"Please Enter valid phone_no"})

            otp = random.randint (100000, 999999)
            body_msg = 'Your OTP is {} . OTP is valid for 1 hour or 1 successfull attempt.'.format (
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
            user.save ()

            
        except Exception as e:
            raise ValidationError(e)

        return ({"data":None, "code":status.HTTP_200_OK, "message":"OTP Sent Successfully"})

    def verify_otp(self, request, format=None):
        # self.validate_otp_data (request.data)
        tz = pytz.timezone ('Asia/Kolkata')
        current_time = datetime.now (tz)
        now_date = current_time.strftime ('%m/%d/%y')
        now_time = current_time.strftime ('%H:%M')

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
                    otp_send_time = otp_send_time.astimezone (tz) + timedelta (hours=1)

                    otp_date = datetime.strftime (otp_send_time, '%m/%d/%y')
                    otp_time = datetime.strftime (otp_send_time, '%H:%M')

                    if now_date == otp_date and now_time <= otp_time:
                        user.otp_varification = True
                        user.save()
                        return {"data": None, "code": status.HTTP_200_OK, "message": OTP_VERIFID}
                    else:
                        return {"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": OTP_EXPIRED}
                else:
                    return ({"data":None, "code":status.HTTP_400_BAD_REQUEST, "message":WRONG_OTP})
            else:
                return ({"data":None, "code":status.HTTP_400_BAD_REQUEST, "message":NUMBER_ALREADY_VARIFIED})        
            
        else:
            return {"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": DETAILS_INCORRECT}

    def get_profile_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        context = {"profile_user_id":user_obj.id , "logged_in_user":request.user.id}
        serializer = GetUserProfileSerializer(user_obj, context = context)
        # payload = jwt_payload_handler(user_obj)
        # token = jwt.encode(payload, settings.SECRET_KEY)
        user_details = serializer.data
        user_details['wallet_token'] = user_obj.wallet_token
        return ({"data":user_details, "code":status.HTTP_200_OK, "message":"User Profile fetched Successfully"})
        
    
    def get_page_profile_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        context = {"profile_user_id":user_obj.id , "logged_in_user":request.user.id}
        serializer = GetUserPageProfileSerializer(user_obj, context = context)
        payload = jwt_payload_handler(user_obj)
        token = jwt.encode(payload, settings.SECRET_KEY)
        user_details = serializer.data
        user_details['token'] = token
        return ({"data":user_details, "code":status.HTTP_200_OK, "message":"User Profile fetched Successfully"})


    def update_profile_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        serializer = UpdateUserProfileSerializer(user_obj, data= request.data)
        try:
            new_email = request.data['email']
            email_exists = User.objects.filter(email = new_email)
            if serializer.is_valid():
                if not email_exists:
                    serializer.save()
                    return ({"data":serializer.data, "code":status.HTTP_200_OK, "message":"User Profile Updated Successfully"})
                else:
                    return ({"data":serializer.errors, "code":status.HTTP_400_BAD_REQUEST, "message":"Email already exists"})
        except KeyError:
            pass
        if serializer.is_valid():
                serializer.save()
                return ({"data":serializer.data, "code":status.HTTP_200_OK, "message":"User Profile Updated Successfully"})
        return ({"data":serializer.errors, "code":status.HTTP_400_BAD_REQUEST, "message":BAD_REQUEST})

    def get_wallet_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        context = {"profile_user_id":user_obj.id , "logged_in_user":request.user.id}
        serializer = GetUserWalletSerializer(user_obj, context = context)
        return ({"data":serializer.data, "code":status.HTTP_200_OK, "message":"User Wallet fetched Successfully"})


    def update_wallet_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        serializer = UpdateUserWalletSerializer(user_obj, data= request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data":serializer.data, "code":status.HTTP_200_OK, "message":"User Wallet saved Successfully"})
        return ({"data":serializer.errors, "code":status.HTTP_400_BAD_REQUEST, "message":BAD_REQUEST})

    def encrypted_wallet_token(self):
        random_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        encrypted_text = cipher_suite.encrypt(random_token.encode('ascii'))
        encrypted_text = base64.urlsafe_b64encode(encrypted_text).decode("ascii") 
        return encrypted_text

    def decrypt_wallet_token_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        encrypted_wallet_token = base64.urlsafe_b64decode(user_obj.wallet_token)
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        decoded_text = cipher_suite.decrypt(encrypted_wallet_token).decode("ascii")
        response_data = {}
        response_data['token'] = decoded_text
        return ({"data": response_data , "code":status.HTTP_200_OK, "message":"Wallet token decrypted Successfully"})

    def get_bookmarks_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        if user_obj:
            try:
                if request.GET.get('type') is None:
                    user_bookmarks = UserBookmarks.objects.filter(user = user_obj).all()
             
                else:
                    user_bookmarks = UserBookmarks.objects.filter(user = user_obj, post__type= request.GET['type']).all()
                    
                if user_bookmarks:
                    context = {"profile_user_id":user_obj.id , "logged_in_user":request.user.id}
                    serializer = GetUserBookmarksSerializer(user_bookmarks, many=True, context = context)
                    preference = serializer.data
                else:
                    preference = None
            except UserPreferences.DoesNotExist:
                preference = None
            return ({"data":preference, "code":status.HTTP_200_OK, "message":"User Bookmarks fetched Successfully"})
        return ({"data": [{error: 'User not found'}], "code":status.HTTP_400_BAD_REQUEST, "message":BAD_REQUEST})
    
    def create_bookmark_by_token(self, request, format=None):
        post_exist = UserBookmarks.objects.filter(user=request.user, post=request.data['post']).exists()
        if not post_exist:
            serializer = CreateUpdatePostsSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                res_data = GetUserBookmarksSerializer(UserBookmarks.objects.get(id = serializer.data['id'])).data
                return ({"data": res_data, "code": status.HTTP_201_CREATED, "message": "Bookmark created successfully"})
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": "Oops! Something went wrong."})
        return ({"data": [], "code": status.HTTP_400_BAD_REQUEST, "message": "Bookmark alrerady there."})
        
    def delete_bookmark_by_token(self, request, pk, format=None):
        post_exist = UserBookmarks.objects.filter(user=request.user,post=pk)
        if not post_exist.exists():
            return ({"code":status.HTTP_400_BAD_REQUEST, "message":"Bookmark not exists"})
        else:
            post_exist.delete()
            return ({"code":status.HTTP_200_OK, "message":"Bookmark deleted successfully"})    

    def get_preferences_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        if user_obj:
            try:
                user_preferences_obj = UserPreferences.objects.get(user = user_obj)
                context = {"profile_user_id":user_obj.id , "logged_in_user":request.user.id, "preference_id": user_preferences_obj.id}
                serializer = GetUserPreferencesSerializer(user_preferences_obj, context = context)
                preference = serializer.data
            except UserPreferences.DoesNotExist:
                preference = None
            return ({"data":preference, "code":status.HTTP_200_OK, "message":"User Preferences fetched Successfully"})
        return ({"data": [{error: 'User not found'}], "code":status.HTTP_400_BAD_REQUEST, "message":BAD_REQUEST})


    def update_preferences_by_token(self, request, format=None):
        user_obj = User.objects.get(id = request.user.id)
        if user_obj:
            try:
                user_preferences_obj = UserPreferences.objects.get(user = user_obj)
            except UserPreferences.DoesNotExist:
                user_preferences_obj = UserPreferences.objects.create(user=user_obj)
            
            serializer = UpdateUserPreferencesUpdateSerializer(user_preferences_obj, data= request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                return ({"data":serializer.data, "code":status.HTTP_200_OK, "message":"User Preferences saved Successfully"})
            return ({"data":serializer.errors, "code":status.HTTP_400_BAD_REQUEST, "message":BAD_REQUEST})
        return ({"data": [{error: 'User not found'}], "code":status.HTTP_400_BAD_REQUEST, "message":BAD_REQUEST})

    def get_profile_by_username(self, request, format=None):
        try:
            user_obj = User.objects.get(custom_username = request.data['custom_username'])
        except User.DoesNotExist:
            return ({"data":None, "code":status.HTTP_400_BAD_REQUEST, "message":RECORD_NOT_FOUND})
        context = {"profile_user_id":user_obj.id , "logged_in_user":request.user.id}
        serializer = GetUserProfileSerializer(user_obj, context = context)
        return ({"data":serializer.data, "code":status.HTTP_200_OK, "message":"User Profile fetched Successfully"})
    
    def logout(self, request, format=None):

        validated_data = self.validate_logout_data(request)
        try:
            jwt_token_str = request.META['HTTP_AUTHORIZATION']
            jwt_token = jwt_token_str.replace('Bearer', '')
            user_detail = jwt.decode(jwt_token, None, None)
            user = User.objects.get(pk=user_detail['user_id'])

            user_session_instance = self.get_user_session_object(user.pk, request.headers.get('device-type'), request.data.get('device_id'))

            if user_session_instance:
                user_session = self.create_update_user_session(user, None, request)
                return ({"data": None, "code": status.HTTP_200_OK, "message": "LOGOUT_SUCCESSFULLY"})
            else:
                return ({"data":None, "code":status.HTTP_400_BAD_REQUEST, "message":"RECORD_NOT_FOUND"})

        except User.DoesNotExist:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "RECORD_NOT_FOUND"})


    def get_referred_users_list(self, request, pk, format=None):
        usr_obj = User.objects.filter(referred_by = pk)
        serializer = UserLoginDetailSerializer(usr_obj, many = True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": "Data Fetched Successfully."})
