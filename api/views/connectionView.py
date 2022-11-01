from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from rest_framework.viewsets import ModelViewSet

from api.models import User, ConfineUsers, UserCustomLists, UserCustomGroupMembers
from api.models.userFollowersModel import UserStories, UserFollowers
from api.serializers import ConfineModelSerializer, UserCustomListsModelSerializer, \
    UserCustomGroupMembersModelSerializer
from api.serializers.connections import UserStoriesModelSerializer
from api.services.connections import ConnectionService

connectionService = ConnectionService()




class FollowView(APIView):

    def post(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.follow(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class UnfollowView(APIView):
    def delete(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.unfollow(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class RemoveFollowerView(APIView):
    def delete(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.remove_follower_by_user_id(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)



class GetFollowRequestList(APIView):
    def get(self, request, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.get_follow_request_list(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UpdateFollowRequestView(APIView):
    def put(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.update_follow_request_status(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetFollowerListView(APIView):
    def get(self, request, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.get_follower_list(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetFollowingListView(APIView):
    def get(self, request,format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.get_following_list(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class DeleteFollowRequestView(APIView):
    def delete(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.delete_follow_request(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class UpdatePrivacyStatusView(APIView):
    def put(self, request, format=None):
        """
        Retun all the Posts.
        """
        result = connectionService.update_privacy_status(request, format=None)
        return Response(result, status=status.HTTP_200_OK)


class UserStoriesModelViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, ]
    queryset = UserStories.objects.all()
    serializer_class = UserStoriesModelSerializer

    def get_queryset(self):
        request = self.request
        follower = UserFollowers.objects.filter(user=request.user.id, request_status=True).values_list('follower')
        following = UserFollowers.objects.filter(follower=request.user.id, request_status=True).values_list('user')
        users = following.union(follower)
        return UserStories.objects.filter(user__in=users)


class confineUserModelViewSet(ModelViewSet):
    serializer_class = ConfineModelSerializer
    permission_classes = [IsAuthenticated, ]
    queryset = ConfineUsers.objects.all()

    def get_queryset(self):
        return ConfineUsers.objects.filter(main_user=self.request.user)

class UserCustomListsModelViewSet(ModelViewSet):
    serializer_class = UserCustomListsModelSerializer
    permission_classes = [IsAuthenticated, ]
    queryset = UserCustomLists.objects.all()

    def get_queryset(self):
        return UserCustomLists.objects.filter(user=self.request.user)


class UserCustomGroupMembersModelViewSet(ModelViewSet):
    serializer_class = UserCustomGroupMembersModelSerializer
    permission_classes = [IsAuthenticated, ]
    queryset = UserCustomGroupMembers.objects.all()

    def get_queryset(self):
        return UserCustomGroupMembers.objects.filter(user_custom_lists__user=self.request.user)
