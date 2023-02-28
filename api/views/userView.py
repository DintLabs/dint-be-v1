from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema, uritemplate
from rest_framework.viewsets import ModelViewSet

from api.models import UserReferralWallet
from api.serializers import UserReferralWalletModelSerializer
from api.services.user import UserService

userService = UserService()

class SignupView(APIView):
    permission_classes = (AllowAny,)
    schema = AutoSchema(manual_fields=[
        coreapi.Field(
            "email",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "phone_no",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "password",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "first_name",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "last_name",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "middle_name",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "gender",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "dob",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "role",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "longitude",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "latitude",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "visit_start_time",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "visit_end_time",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "about_us",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "patient_check_time",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "address",
            required=True,
            location="form",
            schema=coreschema.String()
        )
    ])
    def post(self, request, format=None):
        """
        Create User/ Signup User
        """
        result = userService.sign_up(request)
        return Response(result, status=status.HTTP_200_OK)

class VarifyOtpView(APIView):
    permission_classes = (AllowAny,)
    schema = AutoSchema(manual_fields=[
        coreapi.Field(
            "id",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "otp",
            required=True,
            location="form",
            schema=coreschema.String()
        )
    ])
    def post(self, request, format=None):
        """
        verify otp
        """
        result = userService.verify_otp(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class SendOtpForOldUser(APIView):
    permission_classes = (AllowAny,)
    schema = AutoSchema(manual_fields=[
        coreapi.Field(
            "phone_no",
            required=True,
            location="form",
            schema=coreschema.String()
        )
    ])
    def post(self, request, format=None):
        """
        Send OTP
        """
        result = userService.send_otp_for_old_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class LoginView(APIView):
    permission_classes = (AllowAny,)
    schema = AutoSchema(manual_fields=[
        coreapi.Field(
            "email",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "password",
            required=True,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "device_id",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "device-type",
            required=False,
            location="header",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "app-version",
            required=False,
            location="header",
            schema=coreschema.String()
        )
    ])

    def post(self, request, format=None):
        """
        Login
        """
        result = userService.login(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class ProfileView(APIView):
    """
    APIs for Fetching the profile and Updating it by Token
    """

    def get(self, request, format=None):
        """
        Get User Profile By Token.
        """
        result = userService.get_profile_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
    def put(self, request, format=None):
        """
        Login
        """
        result = userService.update_profile_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserWalletView(APIView):
    """
    APIs for Fetching the user wallet and Updating it by Token
    """
   
    def get(self, request, format=None):
        """
        Get User Wallet By Token.
        """
        result = userService.get_wallet_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
    def put(self, request, format=None):
        """
        Login
        """
        result = userService.update_wallet_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserDecryptWalletTokenView(APIView):
    """
    APIs for Decrypting the user wallet token
    """
    
    def get(self, request, format=None):
        """
        Login
        """
        result = userService.decrypt_wallet_token_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class PageProfileView(APIView):

    """
    APIs for Fetching the profile and Updating it by Token
    """

    def get(self, request, format=None):
        """
        Get User Profile By Token.
        """
        result = userService.get_page_profile_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class ProfileUsernameView(APIView):
    """
    APIs for Fetching the profile and Updating it by Token
    """
    permission_classes = (AllowAny,)
    def post(self, request, format=None):
        """
        Get User Profile By Token.
        """
        result = userService.get_profile_by_username(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    

class LogoutView(APIView):
    """
    Logout
    """
    schema = AutoSchema(manual_fields=[

        coreapi.Field(
            "device-type",
            required=False,
            location="header",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "device_id",
            required=False,
            location="form",
            schema=coreschema.String()
        ),
        coreapi.Field(
            "app-version",
            required=False,
            location="header",
            schema=coreschema.String()
        )

    ])

    def post(self, request, format=None):
        # simply delete the token to force a login
        result = userService.logout(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserPreferencesView(APIView):
    """
    APIs for Fetching the user preferences and Updating it by Token
    """

    def get(self, request, format=None):
        """
        Get User Preferences By Token.
        """
        result = userService.get_preferences_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
    
    def put(self, request, format=None):
        """
        Login
        """
        result = userService.update_preferences_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserBookmarksView(APIView):
    """
    APIs for Fetching the user bookmarks by Token
    """

    def get(self, request, format=None):
        """
        Get User Bookmarks By Token.
        """
        result = userService.get_bookmarks_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create User Bookmark By Token.
        """
        result = userService.create_bookmark_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self,request,pk,format=None):
        """
        Delete User Bookmark By Token.
        """
        
        result = userService.delete_bookmark_by_token(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserReferralWalletModelViewSet(ModelViewSet):
    serializer_class = UserReferralWalletModelSerializer
    permission_classes = [IsAuthenticated, ]
    queryset = UserReferralWallet.objects.all()

    def get_queryset(self):
        return UserReferralWallet.objects.filter(referred_by=self.request.user)


class SearchAnyUserView(APIView):

    def get(self, request, format=None):
        """
        Retrieve a User 
        """
        result = userService.search_any_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)


class CloseFriendsView(APIView):
    """
    APIs for Fetching the user bookmarks by Token
    """

    def get(self, request, format=None):
        """
        Get User close friends By Token.
        """
        result = userService.get_closefriends(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create User close friends By Token.
        """
        result = userService.create_closefriends(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self,request,pk,format=None):
        """
        Delete User close friends By Token.
        """
        
        result = userService.delete_closefriends(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UserUpdateStatusView(APIView):

    def put(self, request, format=None):
        """
        update user status
        """
        result = userService.update_user_status_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)



class UserSendDint(APIView):
    def post(self, request, format=None):
        result = userService.send_dint_token(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class UserDintReward(APIView):
    def post(self, request, format=None):
        result = userService.send_reward_by_token(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class WithdrawDint(APIView):
    """
    APIs for Withdraw the dint token
    """
    def post(self, request, format=None):
        result = userService.withdraw_dint_token(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class VerifyIdentity(APIView):
    """
    APIs for identity verify
    """
    def post(self, request, format=None):
        result = userService.verify_identity(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class ValidateUserReferral(APIView):
    """
    APIs to validating referral code
    """
    permission_classes = (AllowAny,)
    def post(self, request, format=None):
        result = userService.validate_user_referral(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class AddReferralCode(APIView):
    """
    APIs to validating referral code
    """
    def post(self, request, format=None):
        result = userService.add_user_referral(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class UserReferralCode(APIView):
    """
    APIs to validating referral code
    """
    def get(self, request, format=None):
        result = userService.user_referral_code_by_token(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class SendVerificationEmail(APIView):
    """
    APIs for send verification email
    """
    def put(self, request, pk, format=None):
        result = userService.send_verification_email_by_token(request, pk, format=None)
        return Response(result, status = status.HTTP_200_OK)
   
class ValidateVerificationtoken(APIView):
    """
    API for validating verification token
    """
    def post(self, request, format=None):
        result = userService.validate_verification_token(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class TrackUserIpAddress(APIView):
    """
    API to get ip address by token
    """
    def get(self, request, format=None):
        result = userService.track_ip_address(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class UserSuggestions(APIView):
    """
    API to get suggestions
    """
    def get(self, request, format=None):
        result = userService.get_suggestions(request, format=None)
        return Response(result, status = status.HTTP_200_OK)

class GetUserReferralId(APIView):
    """
    API to get referral id
    """
    def get(self, request, format=None):
        result = userService.get_referral_id_by_token(request, format=None)
        return Response(result, status = status.HTTP_200_OK)
    
class GetUnreadNotifications(APIView):
    '''
    API to get unread notifications for user
    '''
    def get(self, request, format=None):
        result = userService.get_unread_notification_list_by_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class ReadNotification(APIView):
    '''
    API to read notification
    '''
    def get(self, request,pk, format=None):
        result = userService.read_notification(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)