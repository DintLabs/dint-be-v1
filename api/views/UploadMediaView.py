from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi
from api.services.uploadMedia import UploadMediaService
upload_media = UploadMediaService()

uploadmedia_schema = AutoSchema(manual_fields=[
    coreapi.Field(
        "media",
        required=True,
        location="form",
        type="file"
    )
])

class UploadMediaView(APIView):
    permission_classes = (AllowAny,)
    schema = uploadmedia_schema
    def post(self, request, format=None):
        """
        Create Role.
        """
        result = upload_media.create_upload_media(request, format=None)
        return Response(result, status=result["code"])

class DeleteMediaView(APIView):
    def delete(self, request, pk, format=None):
        result = upload_media.delete_media(request, pk, format=None)
        return Response(result, status=result["code"])