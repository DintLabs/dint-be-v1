import json
from channels.generic.websocket import WebsocketConsumer
import json
from asgiref.sync import async_to_sync
from api.serializers.chat import CreateUpdateMessageSerializer, GetSocketMessageSerializer
from api.models.messagesModel import Messages
from channels.generic.websocket import AsyncWebsocketConsumer
from api.models import User
from channels.db import database_sync_to_async
from django.db.models import F
from datetime import datetime

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope['user']
        await self.connection_incre(user)

        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = 'chat_%s' % self.room_name

        await(self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        user = self.scope['user']
        await self.connection_decre(user)
        await self.update_user_status(user)

        # Leave room group
        await(self.channel_layer.group_discard)(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message = text_data_json['message']
        except:
            message = text_data_json
        
        # Send notification on message send
        await(self.channel_layer.group_send)(
            self.room_group_name,
            {
                'type': 'send_notification',
                'message': message
            }
        )
        await(self.channel_layer.group_send)(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message
            }
        )

    async def send_notification(self, event):
        message = event['message']
        user = self.scope['user']

        # Send message to WebSocket on new message
        text = 'Got new message from '+ user.name
        await self.send(json.dumps({
            "type": "notification",
            "event": text,
            "message": message
        }))
        
        

    async def chat_message(self, event):
        message = event['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))

    async def chat_message(self, event):
        message = event['message']
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))

    async def _create_message(self, message_data):
        """
        Create New Message. 
        """
        try:
            message_data = json.loads(message_data)
        except:
            None
        serializer = CreateUpdateMessageSerializer(data=message_data)
        if serializer.is_valid():
            serializer.save()
            res_obj = Messages.objects.get(id = serializer.data['id'])
            result_data = dict(GetSocketMessageSerializer(res_obj).data)
            return str(result_data)
        else:
            return str(serializer.errors)

    @database_sync_to_async
    def connection_incre(self, user):
        user_connection = User.objects.filter(email = user).update(connections = F('connections')+1, is_online=True, last_login = None)

    @database_sync_to_async
    def connection_decre(self, user):
        user_connection = User.objects.filter(email = user).update(connections = F('connections')-1)

    @database_sync_to_async
    def update_user_status(self, user):
        user = User.objects.get(email = user)
        if user.connections > 0:
            user.is_online = True
            user.last_login = None
            user.save()
        else:
            user.is_online = False
            user.last_login = datetime.now()
            user.save()

            