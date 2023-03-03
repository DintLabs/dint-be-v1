from rest_framework import serializers
from api.models import UploadMedia

from django.core.exceptions import ValidationError

import base64

class UploadMediaListSerializer(serializers.ModelSerializer):

    class Meta:
        model = UploadMedia
        fields = ("id" ,'user', "media_file_name", "file_type", "thumbnail", "media_file_url")
    
    
class UploadMediaDetailsSerializer(serializers.ModelSerializer):
    """
    Details of uploaded media and its connected with FeedMediaDetailsSerializer
    """
    class Meta:
        model = UploadMedia
        fields = ("id" , "media_file_name", "file_type", "thumbnail", "media_file_url")