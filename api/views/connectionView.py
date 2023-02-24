from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from rest_framework.viewsets import ModelViewSet
from rest_framework import viewsets
from api.models import User, ConfineUsers, UserCustomLists, UserCustomGroupMembers
from api.models.userFollowersModel import UserFollowers
from api.serializers import ConfineModelSerializer, UserCustomListsModelSerializer, \
    UserCustomGroupMembersModelSerializer
from api.services.connections import ConnectionService
import datetime
from django.utils import timezone

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

class confineUserModelViewSet(ModelViewSet):
    serializer_class = ConfineModelSerializer
    permission_classes = [IsAuthenticated, ]
    # queryset = ConfineUsers.objects.all()

    def get_queryset(self):
        return ConfineUsers.objects.filter(main_user=self.request.user)

    def create(self,request):
        main_user = request.data['main_user']
        user_block_type = request.data['user_block_type']
        confine_user = request.data['confine_user']
        
        user = ConfineUsers.objects.filter(main_user = main_user, user_block_type = user_block_type, confine_user = confine_user)
        
        main_usr_obj = User.objects.get(id = main_user)
        confine_usr_obj = User.objects.get(id = confine_user)

        if user.exists():
            res = {
            "data" : [],
            "message": "User already blocked or restricted",
            }
            return Response(res)
        else:
            data = request.data
            confine_user = ConfineUsers.objects.create(main_user = main_usr_obj, user_block_type = user_block_type, confine_user = confine_usr_obj)
            
            serializer = ConfineModelSerializer(confine_user, data = request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                res = {
                    "data" : serializer.data,
                    "message": "User added to restrict or block successfully",
                    }
                return Response(res)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
       
        remove_user = ConfineUsers.objects.get(id=instance.id)
        remove_user.delete()
       
        res = {
            "message": "User removed successfully",
        }
    
        return Response(res)

class UserCustomListsModelViewSet(viewsets.ModelViewSet):
    serializer_class = UserCustomListsModelSerializer
    permission_classes = [IsAuthenticated, ]

    def get_queryset(self):
        return UserCustomLists.objects.filter(user=self.request.user)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        members = UserCustomGroupMembers.objects.filter(user_custom_lists=instance)
        serializer = UserCustomGroupMembersModelSerializer(members, many=True)
        
        res = {
            "data" : serializer.data,
            "message": "List Fethced Successfully",
        }
    
        return Response(res)
       
class UserCustomGroupMembersModelViewSet(ModelViewSet):
    serializer_class = UserCustomGroupMembersModelSerializer
    permission_classes = [IsAuthenticated, ]
    queryset = UserCustomGroupMembers.objects.all()

    def get_queryset(self):
        return UserCustomGroupMembers.objects.filter(user_custom_lists__user=self.request.user)

    def create(self,request):
        data = request.data
        list_data = list(data)

        for i in list_data:
            
            custom_list = i['user_custom_lists']
            member = i['member']
            custom_user_obj = UserCustomLists.objects.get(id = custom_list)
            member_obj = User.objects.get(id = member)

            list_create = UserCustomGroupMembers.objects.create(user_custom_lists = custom_user_obj , member = member_obj)

        res = {
                "message" : "Member added successfully"
              }
        return Response(res)
