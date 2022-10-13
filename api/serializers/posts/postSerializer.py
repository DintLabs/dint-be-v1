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


    class Meta(object):
        model = Posts
        fields = '__all__'