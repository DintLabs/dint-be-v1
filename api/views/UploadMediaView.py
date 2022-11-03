from rest_framework.permissions import  IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from api.models import UploadMedia
from api.serializers import UploadMediaListSerializer


class UploadMediaView(ModelViewSet):
    permission_classes = [IsAuthenticated, ]
    queryset = UploadMedia.objects.all()
    serializer_class = UploadMediaListSerializer
    http_method_names = ['post', 'delete']
