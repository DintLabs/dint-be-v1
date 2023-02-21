from rest_framework import serializers
from api.models import *
from api.models.messageNotificationModel import *
from api.serializers.user import UserLoginDetailSerializer


class CreateUpdateMessageSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Messages
        fields = '__all__'


class CreateUpdateNotificationSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Notifications
        fields = '__all__'


class UpdateMessageSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Messages
        fields = ['content']



class GetMessageSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    reciever = UserLoginDetailSerializer()
    sender = UserLoginDetailSerializer()
    show_type = serializers.SerializerMethodField()
    chat_room = serializers.SerializerMethodField()
    class Meta(object):
        model = Messages
        fields = '__all__'

    def get_show_type(self, obj):
        user_id = self.context.get('user_id')
        if user_id == obj.reciever.id:
            return 1
        elif user_id == obj.sender.id:
            return 2
        else:
            return 0

    def get_chat_room(self, obj):
        chat_room_obj = _get_chat_room(obj.sender.id, obj.reciever.id)
        return chat_room_obj.id



# GetNotificationSerializer
class GetNotificationSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    message = GetMessageSerializer()
    # type_of_notification = serializers.SerializerMethodField()
    class Meta(object):
        model = Notifications
        fields = '__all__'


class GetSocketMessageSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    # reciever = UserLoginDetailSerializer()
    # sender = UserLoginDetailSerializer()
    show_type = serializers.SerializerMethodField()
    chat_room = serializers.SerializerMethodField()
    class Meta(object):
        model = Messages
        fields = '__all__'

    def get_show_type(self, obj):
        user_id = self.context.get('user_id')
        if user_id == obj.reciever.id:
            return 1
        elif user_id == obj.sender.id:
            return 2
        else:
            return 0

    def get_chat_room(self, obj):
        chat_room_obj = _get_chat_room(obj.sender.id, obj.reciever.id)
        return chat_room_obj.id

class ChatListSerializer(serializers.ModelSerializer):

    latest_message = serializers.SerializerMethodField()
    chat_room = serializers.SerializerMethodField()
    class Meta(object):
        model = User
        fields = '__all__'

    def get_latest_message(self, obj):
        user1_id = self.context.get('user1_id')
        user2_id = obj.id
        try:
            message1_obj = Messages.objects.filter(reciever = user1_id, sender = user2_id).latest('created_at')
        except:
            message1_obj = None
        try:
            message2_obj = Messages.objects.filter(reciever = user2_id, sender = user1_id ).latest('created_at')
        except:
            message2_obj = None
        if message1_obj is None:
            return GetMessageSerializer(message2_obj).data
        elif message2_obj is None:
            return GetMessageSerializer(message1_obj).data
        elif message1_obj is None and message2_obj is None:
            return None
        else:
            if message1_obj.created_at > message2_obj.created_at:
                return GetMessageSerializer(message1_obj).data
            else:
                return GetMessageSerializer(message2_obj).data

    def get_chat_room(self, obj):
        user1_id = self.context.get('user1_id')
        user2_id = obj.id
        chat_room_obj = _get_chat_room(user1_id, user2_id)
        return chat_room_obj.id


def _get_chat_room(sender, reciever):
    try:
        obj = ChatRoom.objects.get(sender=sender, reciever=reciever)
        return obj
    except ChatRoom.DoesNotExist:
        try:
            obj = ChatRoom.objects.get(sender=reciever, reciever=sender)
            return obj
        except ChatRoom.DoesNotExist:
            obj = ChatRoom()
            obj.sender = User.objects.get(id=sender)
            obj.reciever = User.objects.get(id=reciever)
            obj.save()
            return obj
