from dataclasses import field
from api.models.pageModel import Page
from api.models.userFollowersModel import UserFollowers
from rest_framework import serializers
from api.models.UserStoriesModel import *
from api.models import (User, Posts, PostComments, PostLikes, UserReferralWallet, UserPreferences, ConfineUsers, UserCustomLists, UserCustomGroupMembers, UserCloseFriends, UserStories, UserIdentity)
from api.models.userFollowersModel import *
# from api.serializers.connections import *
from api.models.userBookmarksModel import UserBookmarks
from django.core.exceptions import ValidationError
from api.models.messageNotificationModel import Notifications
from django.http import JsonResponse
from django.forms.models import model_to_dict
import datetime
from django.utils import timezone

class UserLoginDetailSerializer(serializers.ModelSerializer):
    """
    Return the details of Login User.
    """
    class Meta(object):
        model = User
        fields = (
            'id', 'email', 'first_name', 'last_name', 'phone_no', 'is_active', 'is_deleted', 'profile_image','display_name', 'custom_username', 'is_private' , 'able_to_be_found')

class UserCreateUpdateSerializer(serializers.ModelSerializer):
    """
    create/update user .
    """
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
        'id', 'email', 'phone_no' ,'custom_username', 'display_name', 'bio', 'location', 'website_url', 'amazon_wishlist', 'profile_image','city', 'twitter', 'instagram', 'discord', 'banner_image', 'location', 'is_private', 'able_to_be_found')


class GetUserPageSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    class Meta(object):
        model = Page
        fields = '__all__'

class UserStoriesModelSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model = UserStories
        exclude = ['updated_at', ]
        
    def get_name(self, obj):
        return obj.user.name

class UserFollowersSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    # user = UserLoginDetailSerializer()
    follower = UserLoginDetailSerializer()

    class Meta(object):
        model = UserFollowers
        fields = '__all__'

class UserFollowingSerializer(serializers.ModelSerializer):
    user = UserLoginDetailSerializer()
    # follower = UserLoginDetailSerializer()

    class Meta(object):
        model = UserFollowers
        fields = '__all__'

# class GetUserStoriesModelSerializer(serializers.ModelSerializer):
#     user_stories = serializers.SerializerMethodField()
   
#     class Meta(object):
#         model = User
#         fields = (
#             'id', 'profile_image', 'display_name', 'custom_username',  'user_stories')

#     def get_user_stories(self, obj):
#         print("story_obj", obj)
        # # logged_in_user = self.context.get('logged_in_user')
        # follower = UserFollowers.objects.filter(user=logged_in_user, request_status=True).values_list('follower')
        # following = UserFollowers.objects.filter(follower=logged_in_user, request_status=True).values_list('user')
        # users = following.union(follower)

        # expire_time = timezone.now() - datetime.timedelta(hours=24)
        # userstories = UserStories.objects.filter(user__in=users, created_at__gt = expire_time)
        # serializer = UserStoriesModelSerializer(instance = userstories, many=True).data
        # return serializer

class GetUserProfileSerializer(serializers.ModelSerializer):
    """
    Update User Profile Serializer
    """
    user_posts = GetUserPostsSerializer(many=True)
    is_followed = serializers.SerializerMethodField()
    user_stories = serializers.SerializerMethodField()
    # user_stories = GetUserStoriesModelSerializer(many=True)
    user_follower = UserFollowersSerializer(many = True)
    user_following = UserFollowingSerializer(many= True)

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
    
    def get_user_stories(self, obj):
        profile_user_id = self.context.get('profile_user_id')
        expire_time = timezone.now() - datetime.timedelta(hours=24)
        userstories = UserStories.objects.filter(user = profile_user_id, created_at__gt = expire_time)
        serializer = UserStoriesModelSerializer(instance = userstories, many=True).data
        return serializer

    class Meta:
        model = User
        fields = (
        'id', 'custom_username', 'display_name', 'bio', 'location', 'website_url', 'amazon_wishlist', 'profile_image','city', 'twitter', 'instagram', 'discord', 'banner_image', 'user_posts', 'location', 'is_followed','is_private','is_online', 'last_login','is_active', 'user_stories', 'user_follower', 'user_following')

class UpdateUserWalletSerializer(serializers.ModelSerializer):
    """
    Update User Wallet Serializer
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
    is_followed = serializers.SerializerMethodField()
    user_page = GetUserPageSerializer(many=True)

    class Meta:
        model = User
        fields = (
        'id', 'email', 'phone_no', 'custom_username', 'display_name', 'bio', 'location', 'website_url', 'amazon_wishlist', 'profile_image','city', 'twitter', 'instagram', 'discord', 'banner_image', 'location', 'is_followed', 'is_private', 'user_page', 'is_online', 'last_login','is_active', 'able_to_be_found')

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
    """
    This is for Retrieving user referral wallet
    """
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
    user = UserLoginDetailSerializer()
    total_likes = serializers.SerializerMethodField()
    total_comments = serializers.SerializerMethodField()
    like_post = GetUserPostLikeSerializer(many=True)
    post_comment = GetUserPostsCommentSerializer(many=True)

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
            
class GetUserBookmarksSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving user Bookmarks
    """
    post = GetPostSerializer()
    user = UserLoginDetailSerializer()
  
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

    class Meta:
        many = True
        model = UserBookmarks
        fields = '__all__'

class CreateUserBookmarksSerializer(serializers.ModelSerializer):
    """
    This is for creating user Bookmarks 
    """
    class Meta:
        model = UserBookmarks
        fields = '__all__'

class ConfineModelSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving confined user
    """
    main_user_details = serializers.SerializerMethodField()
    confine_user_details = serializers.SerializerMethodField()
   
    class Meta(object):
        model = ConfineUsers
        fields = "__all__"
    
    def get_main_user_details(self, obj):
        main_user_details = UserLoginDetailSerializer(obj.main_user).data
        return main_user_details

    def get_confine_user_details(self, obj):
        main_user_details = UserLoginDetailSerializer(obj.confine_user).data
        return main_user_details

class UserCustomListsModelSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving user custom lists
    """
    people = serializers.SerializerMethodField()

    class Meta:
        model = UserCustomLists
        fields = "__all__"

    def get_people(self, obj):
        return UserCustomGroupMembers.objects.filter(user_custom_lists=obj).count()


class UserCustomGroupMembersModelSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving user custom group members
    """
    member_details = serializers.SerializerMethodField()
    list_name = serializers.SerializerMethodField()
   
    class Meta(object):
        model = UserCustomGroupMembers
        fields = "__all__"

    def get_member_details(self, obj):
        member_details = UserLoginDetailSerializer(obj.member).data
        return UserLoginDetailSerializer(obj.member).data

    def get_list_name(self, obj):
        return obj.user_custom_lists.name


class ProfileByUsernameSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving profile by user name
    """
    is_followed = serializers.SerializerMethodField()
    total_posts = serializers.SerializerMethodField()
    total_followers = serializers.SerializerMethodField()
    total_following = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = fields = (
        'id', 'custom_username', 'display_name', 'bio', 'location', 'website_url', 'amazon_wishlist', 'profile_image','city', 'twitter', 'instagram', 'discord', 'banner_image', 'total_posts', 'location', 'is_followed','is_private','is_online', 'connections', 'last_login', 'is_active', 'total_followers', 'total_following')

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
    
    def get_total_posts(self, obj):
        logged_in_user = self.context.get('profile_user_id')
        total_posts = Posts.objects.filter(user = logged_in_user).all().count()
        return total_posts
    
    def get_total_followers(self, obj):
        logged_in_user = self.context.get('profile_user_id')
        total_followers = UserFollowers.objects.filter(user = logged_in_user, request_status = True).all().count()
        return total_followers
   
    def get_total_following(self, obj):
        logged_in_user = self.context.get('profile_user_id')
        total_following = UserFollowers.objects.filter(follower = logged_in_user, request_status = True).all().count()
        return total_following
  

class UserCloseFriendsSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving user close friends list
    """
    class Meta:
        model = UserCloseFriends
        fields = "__all__"

class UserStatusUpdateSerializer(serializers.ModelSerializer):
    """
    This is for upadating user status
    """
    class Meta:
        model = User
        fields = ('is_online', 'last_login')

class UserIdentitySerializer(serializers.ModelSerializer):
    """
    This is for Retrieving verified user id details
    """
    class Meta:
        model = UserIdentity
        fields = "__all__"


# GetNotificationSerializer
class GetNotificationSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    # type_of_notification = serializers.SerializerMethodField()
    class Meta(object):
        model = Notifications
        fields = '__all__'
