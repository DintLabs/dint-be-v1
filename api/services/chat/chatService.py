from curses import use_default_colors
from curses.ascii import US
from api.models import Role
from api.models.postLikesModel import PostLikes
from api.models.postsModel import Posts
from api.models.userFollowersModel import UserFollowers
from api.serializers.posts import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.postMessages import *
from api.serializers.chat import *
from .chatBaseService import ChatBaseService
from django.db.models import Q

class ChatService (ChatBaseService):
    """
    Create, Retrieve, Update or Delete a Posts instance and Return all Posts.
    """

    def __init__(self):
        pass

    def get_chat_by_user(self, request, pk, format=None):
        """
        Return all the Posts.
        """
        messages_obj = Messages.objects.filter(sender = request.user.id, reciever = pk) |  Messages.objects.filter(sender = pk, reciever = request.user.id)
        messages_obj = messages_obj.order_by('-created_at')
        context = {"user_id":request.user.id}
        #changes is_seen of messages
        Messages.objects.filter(sender = pk, reciever = request.user.id).update(is_seen = True)
        serializer = GetMessageSerializer(messages_obj, many=True, context = context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})



    def get_chat_chunks_by_user(self, request, pk, format=None):
        """
        Return all the Posts.
        """
        if 'limit' in request.data and (request.data['limit'] != "" or request.data['limit'] is not None):
            limit = request.data['limit']
        else:
            limit = 100
        if 'last_message_id' in request.data and (request.data['last_message_id'] != "" or request.data['last_message_id'] is not None):
            messages_obj = Messages.objects.filter(sender = request.user.id, reciever = pk, id__lt = request.data['last_message_id']) |  Messages.objects.filter(sender = pk, reciever = request.user.id, id__lt = request.data['last_message_id'])
        else:
            messages_obj = Messages.objects.filter(sender = request.user.id, reciever = pk) |  Messages.objects.filter(sender = pk, reciever = request.user.id)
        messages_obj = messages_obj.order_by('-created_at')
        if messages_obj.count() > limit:
            messages_obj = messages_obj[:limit]

        context = {"user_id":request.user.id}
        #changes is_seen of messages
        Messages.objects.filter(sender = pk, reciever = request.user.id).update(is_seen = True)
        serializer = GetMessageSerializer(messages_obj, many=True, context = context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def get_chat_chat_list_by_token(self, request, format=None):
        """
        Return all the Posts.
        """
        # received user message
        r_message = list(Messages.objects.filter(reciever = request.user.id).values_list('sender', flat=True))

        s_message = list(Messages.objects.filter(sender = request.user.id).values_list('reciever', flat=True))

        r_message.extend(s_message)
        print('------------------->>')
        print(r_message)
        user_obj = User.objects.filter(id__in = r_message)
        context = {"user1_id":request.user.id}
        serializer = ChatListSerializer(user_obj, many=True, context = context)
        data = serializer.data
        final_data = sorted(data, key=lambda d: d['latest_message']['created_at'], reverse = True) 
        return ({"data": final_data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def search_user(self, request, format=None):
        search_text = request.GET.get('search')
        if search_text is None:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Please provide Search Text"})
        user_obj = User.objects.filter(Q(custom_username__icontains = search_text) | Q(display_name__icontains = search_text))
        follower_list = list(UserFollowers.objects.filter(follower = request.user.id).values_list('user', flat=True))
        public_list = list(User.objects.filter(is_private = False).exclude(id=request.user.id).values_list('id', flat=True))
        follower_list.extend(public_list)
        user_obj = user_obj.filter(id__in = follower_list)
        serializer = UserLoginDetailSerializer(user_obj,many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": OK})

    def create_message(self, request, format=None):
        """
        Create New Posts. 
        """
        serializer = CreateUpdateMessageSerializer(data=request.data)
        if serializer.is_valid ():
            serializer.save()
            res_obj = Messages.objects.get(id = serializer.data['id'])
            result_data = GetMessageSerializer(res_obj).data
            return ({"data": result_data, "code": status.HTTP_201_CREATED, "message": POST_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_messsage(self, request, pk, format=None):
        """
        Delete Posts.   
        """
        try:
            post_obj = Messages.objects.get(id = pk)
        except Messages.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        
        post_obj.delete()
        return ({"code": status.HTTP_200_OK, "message": POST_DELETED})


    def update_message(self, request, pk, format=None):
        """
        Updates Post
        """ 
        data = request.data
        try:
            message_obj = Messages.objects.get(id = pk)
        except Messages.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = UpdateMessageSerializer(message_obj, data=data)
        if serializer.is_valid():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_message(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            message_obj = Messages.objects.get(id = pk)
        except Messages.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        
        context = {"user_id":request.user.id}
        serializer = GetMessageSerializer(message_obj, context = context)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

