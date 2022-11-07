from dataclasses import field
from api.models.pageModel import Page
from api.models.userFollowersModel import UserFollowers
from rest_framework import serializers
from api.models import (User, Posts, PostComments, PostLikes, UserReferralWallet, UserPreferences, ConfineUsers,
                        UserCustomLists, UserCustomGroupMembers)
from api.models.userBookmarksModel import UserBookmarks

from django.core.exceptions import ValidationError


class UserLoginDetailSerializer(serializers.ModelSerializer):
    """
    Return the details of Login User.
    """

    # dob = serializers.DateField(format=DATEFORMAT, input_formats=[DATEFORMAT])

    class Meta(object):
        model = User
        fields = (
            'id', 'email', 'first_name', 'last_name', 'phone_no', 'is_active', 'is_deleted', 'profile_image',
            'display_name', 'custom_username', 'is_private')


class UserCreateUpdateSerializer(serializers.ModelSerializer):
    """
    create/update user .
    """

    # image = serializers.ImageField(required = False, allow_null=True)

    class Meta:
        model = User
        fields = '__all__'


class GetUserPostsCommentSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """

    user = UserLoginDetailSerializer()

    class Meta(object):
        model = PostComments
        fields = '__all__'


class GetUserPostLikeSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """

    user = UserLoginDetailSerializer()

    class Meta(object):
        model = PostLikes
        fields = '__all__'


class GetUserPostsSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving full data
    """
    user = UserLoginDetailSerializer()
    like_post = GetUserPostLikeSerializer(many=True)
    post_comment = GetUserPostsCommentSerializer(many=True)

    class Meta(object):
        model = Posts
        fields = '__all__'


class UpdateUserProfileSerializer(serializers.ModelSerializer):
    """
    Update User Profile Serializer
    """

    class Meta:
        model = User
        fields = (
        'id', 'email', 'phone_no' ,'custom_username', 'display_name', 'bio', 'location', 'website_url', 'amazon_wishlist', 'profile_image',
        'city', 'twitter', 'instagram', 'discord', 'banner_image', 'location', 'is_private')


class GetUserPageSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """

    class Meta(object):
        model = Page
        fields = '__all__'


class GetUserProfileSerializer(serializers.ModelSerializer):
    """
    Update User Profile Serializer
    """
    user_posts = GetUserPostsSerializer(many=True)
    is_followed = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
        'id', 'custom_username', 'display_name', 'bio', 'location', 'website_url', 'amazon_wishlist', 'profile_image',
        'city', 'twitter', 'instagram', 'discord', 'banner_image', 'user_posts', 'location', 'is_followed',
        'is_private')

    def get_is_followed(self, obj):
        profile_user_id = self.context.get('profile_user_id')
        logged_in_user = self.context.get('logged_in_user')
        try:
            u_obj = UserFollowers.objects.get(user=profile_user_id, follower=logged_in_user)
            if u_obj.request_status is True:
                return True
            else:
                return 'Request Sent'
        except:
            return False

class UpdateUserWalletSerializer(serializers.ModelSerializer):
    """
    Update User Wallet Serializer
    """

    class Meta:
        model = User
        fields = ('web3_wallet',)


class GetUserWalletSerializer(serializers.ModelSerializer):
    """
    Get User Wallet Serializer
    """

    class Meta:
        model = User
        fields = ('web3_wallet',)

class UpdateUserPreferencesUpdateSerializer(serializers.ModelSerializer):
    """
    Update User Preference Serializer
    """

    class Meta:
        model = UserPreferences
        fields = ('enable_push_notification', 'enable_email_notification','show_full_text','monthly_news_letter','new_posts_summary','new_posts_summary_time','upcoming_stream_reminder','new_private_msg_summary','new_private_msg_summary_time','receive_less_notification','subscription_notification','new_comment','new_like','language')


class GetUserPreferencesSerializer(serializers.ModelSerializer):
    """
    Get User Preference Serializer
    """

    class Meta:
        model = UserPreferences
        fields = '__all__'

class GetUserPageProfileSerializer(serializers.ModelSerializer):
    """
    Update User Profile Serializer
    """
    # user_posts = GetUserPostsSerializer(many=True)
    is_followed = serializers.SerializerMethodField()
    user_page = GetUserPageSerializer(many=True)

    class Meta:
        model = User
        fields = (
        'id', 'email', 'phone_no', 'custom_username', 'display_name', 'bio', 'location', 'website_url', 'amazon_wishlist', 'profile_image',
        'city', 'twitter', 'instagram', 'discord', 'banner_image', 'location', 'is_followed', 'is_private', 'user_page', 'is_online', 'last_login')

    def get_is_followed(self, obj):
        profile_user_id = self.context.get('profile_user_id')
        logged_in_user = self.context.get('logged_in_user')
        try:
            u_obj = UserFollowers.objects.get(user=profile_user_id, follower=logged_in_user)
            if u_obj.request_status is True:
                return True
            else:
                return 'Request Sent'
        except:
            return False


class UserReferralWalletModelSerializer(serializers.ModelSerializer):
    referred_by = serializers.SerializerMethodField()
    user_referral = serializers.SerializerMethodField()

    class Meta:
        model = UserReferralWallet
        exclude = ['updated_at', ]

    def get_referred_by(self, obj):
        return {
            'name': obj.referred_by.name,
            'email': obj.referred_by.name,
            'referral_id': obj.referred_by.referral_id,
        }

    def get_user_referral(self, obj):
        return {
            'name': obj.user_referral.name,
            'email': obj.user_referral.name,
            'referral_id': obj.user_referral.referral_id,
        }

class GetPostSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving post data
    """
    total_likes = serializers.SerializerMethodField()
    total_comments = serializers.SerializerMethodField()
    is_liked = serializers.SerializerMethodField()
    
    class Meta(object):
        model = Posts
        fields = '__all__'

    def get_total_likes(self, obj):
        try:
            total_likes = PostLikes.objects.filter(post = obj).all().count()
            return total_likes
        except:
            return 0

    def get_total_comments(self, obj):
        try:
            total_comments = PostComments.objects.filter(post = obj).all().count()
            return total_comments
        except:
            return 0

    def is_liked(self, obj):
        logged_in_user = self.context.get('logged_in_user')

        if logged_in_user:
            try:
                u_obj = PostLikes.objects.get(user=logged_in_user, post=obj)
                if u_obj is None:
                    return False
                else:
                    return True
            except:
                return False
        return False
          
class GetUserBookmarksSerializer(serializers.ModelSerializer):

    post = GetPostSerializer()
    user = UserLoginDetailSerializer()
    
    class Meta:
        many = True
        model = UserBookmarks
        fields = '__all__'

class CreateUpdatePostsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserBookmarks
        fields = '__all__'


class ConfineModelSerializer(serializers.ModelSerializer):
    main_user_details = serializers.SerializerMethodField()
    confine_user_details = serializers.SerializerMethodField()
    """
    Return the details of Login User.
    """

    # dob = serializers.DateField(format=DATEFORMAT, input_formats=[DATEFORMAT])

    class Meta(object):
        model = ConfineUsers
        fields = "__all__"

class UserCustomListsModelSerializer(serializers.ModelSerializer):
    people = serializers.SerializerMethodField()

    class Meta:
        model = UserCustomLists
        fields = "__all__"

    def get_people(self, obj):
        return UserCustomGroupMembers.objects.filter(user_custom_lists=obj).count()


class UserCustomGroupMembersModelSerializer(serializers.ModelSerializer):
    member_details = serializers.SerializerMethodField()
    list_name = serializers.SerializerMethodField()
    """
    Return the details of Login User.
    """

    # dob = serializers.DateField(format=DATEFORMAT, input_formats=[DATEFORMAT])

    class Meta(object):
        model = UserCustomGroupMembers
        fields = "__all__"

    def get_member_details(self, obj):
        return UserLoginDetailSerializer(obj.member).data

    def get_list_name(self, obj):
        return obj.user_custom_lists.name