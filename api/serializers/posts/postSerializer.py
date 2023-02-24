from rest_framework import serializers
from api.models import *
from api.serializers.user import UserLoginDetailSerializer


class CreateUpdatePostsSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Posts
        fields = '__all__'


class CreateUpdatePostLikeSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = PostLikes
        fields = '__all__'

class GetPostLikeSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """

    user = UserLoginDetailSerializer()
    class Meta(object):
        model = PostLikes
        fields = '__all__'


class CreateUpdatePostsCommentSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = PostComments
        fields = '__all__'

class GetPostsCommentSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """

    user = UserLoginDetailSerializer()
    class Meta(object):
        model = PostComments
        fields = '__all__'

class GetPostsSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving full data
    """
    user = UserLoginDetailSerializer()
    like_post = GetPostLikeSerializer(many=True)
    post_comment = GetPostsCommentSerializer(many=True)
    bookmarks_count = serializers.SerializerMethodField()
    is_bookmarked = serializers.SerializerMethodField()
    total_likes = serializers.SerializerMethodField()
    total_comments = serializers.SerializerMethodField()

    def get_is_bookmarked(self, obj):
        logged_in_user = self.context.get('logged_in_user')

        if logged_in_user:
            try:
                u_obj = UserBookmarks.objects.get(user=logged_in_user, post=obj)
                if u_obj is None:
                    return False
                else:
                    return True
            except:
                return False
        return False

    def get_bookmarks_count(self, obj):
        try:
            bookmarks_count = UserBookmarks.objects.filter(post=obj).all().count()
            return bookmarks_count
        except:
            return 0

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

    class Meta(object):
        model = Posts
        fields = '__all__'
    
class PostsPaymentSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = PostsPayment
        fields = '__all__'