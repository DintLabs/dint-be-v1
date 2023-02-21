from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from api.services.chat import ChatService

chatService = ChatService()




class ListCreateUpdateDeleteMessageView(APIView):

    def get(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = chatService.get_chat_by_user(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Posts. 
        """
        result = chatService.create_message(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Post
        """
        result = chatService.update_message(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Posts. 
        """
        result = chatService.delete_messsage(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class ListCreateUpdateDeleteNotificationView(APIView):

    def post(self, request, format=None):
        """
        Create New Posts. 
        """
        result = chatService.create_notification(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class ListNotificationsChunksView(APIView):

    def post(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = chatService.get_notification_chunks_by_user(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class ListMessageChunksView(APIView):

    def post(self, request,pk, format=None):
        """
        Retun all the Posts.
        """
        result = chatService.get_chat_chunks_by_user(request,pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetMessageByIDView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = chatService.get_message(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)



class GetChatListByTokenView(APIView):

    def get(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = chatService.get_chat_chat_list_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)



class SearchUserView(APIView):

    def get(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = chatService.search_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetUnseenChatByUser(APIView):

    def get(self, request, format=None):
        """
        Retrieve a Unseen Chat
        """
        result = chatService.get_unseen_chat_list_by_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)
