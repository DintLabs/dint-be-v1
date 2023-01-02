import json
from channels.generic.websocket import WebsocketConsumer
from asgiref.sync import async_to_sync
from api.serializers.chat import CreateUpdateMessageSerializer, GetSocketMessageSerializer
from api.models.messagesModel import Messages

class ChatConsumer(WebsocketConsumer):
    def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = 'chat_%s' % self.room_name

        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )
        self.accept()


    def disconnect(self, close_code):

        # Leave room group
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message = text_data_json['message']
        except:
            message = text_data_json
        #message=self._create_message(message)
        
        async_to_sync(self.channel_layer.group_send)(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message
            }
        )
        
    def chat_message(self, event):
        message = event['message']

        # Send message to WebSocket
        self.send(text_data=json.dumps({
            'message': message
        }))
        


    def _create_message(self, message_data):
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
