from api.models import UploadMedia
from api.serializers.uploadMedia import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from moviepy.editor import *
from PIL import Image
import mimetypes
import os
from .uploadMediaBaseService import UploadMediaBaseService
from api.utils.saveImage import saveImage
from api.models.userModel import *
from django.utils.timezone import datetime

class UploadMediaService(UploadMediaBaseService):
    """
    Create, Retrieve, Update or Delete a media instance and Return all upload media.
    """

    def __init__(self):
        pass

    def create_upload_media(self, request, format=None):
        
        user = request.user
        subscription = request.data['subscription']
       
        user_id = request.user.id
        media_list = []
        if 'folder' in request.data:
            sub_folder = request.data['folder']
            if sub_folder not in ['banners','main-photo','photos','videos']:
                return({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "Folder not Found in S3 Bucket!"})        
        else:
            sub_folder = ''

        today = datetime.now().date()
        if (subscription == "true"):
            print("subscriptions")
            main_folder = "Subscriptions"
            folder = main_folder+'/'+str(user_id)+'/'+sub_folder+'/'+str(today)
        if (subscription == "false"):
            main_folder = "Standard"
            post_type = request.data['media_type']
            if (post_type == "story"):
                media_type = "Stories"
            elif (post_type== "post"):
                media_type = "Posts"
            elif (post_type == "locked"):
                media_type = "Locked"
            elif (post_type == "verifications"):
                media_type = "Verification"
          
            folder = main_folder+'/'+str(user_id)+'/'+media_type+'/'+sub_folder+'/'+str(today)

        
        for im in dict((request.data).lists())['media']: 
            image_url, image_name = saveImage(im, folder)
            media = UploadMedia()
            media.media_file_url = image_url
            media.save()
            media.media_file_name = image_name
            media.file_type = mimetypes.guess_type(im.name)[0]
            user_obj = User.objects.get(id = request.user.id)
            media.user = user_obj
            media.save()
            print(media.user)
            try:
                if ((media.file_type).split("/"))[0] == "video":
                    # self.create_thumbnail("media/upload-media/{}".format(media.media_file_name), media, media.media_file_name)
                    self.create_thumbnail(media.media_file_url, media, media.media_file_name)
            except: 
                pass
            media_list.append(media)

        serializer = UploadMediaListSerializer(media_list, many=True)
        return({"data": serializer.data, "code": status.HTTP_200_OK, "message": "OK"})
            

    
    def delete_media(self, request, pk, format=None):
        media_obj = UploadMedia.objects.get(id=pk)
        media_obj.delete()
        return({"data":None, "code":status.HTTP_200_OK, "message":"Media Deleted Successfully!!"})

    def create_thumbnail(self, path, instance, file_name):
        try:
            clip = VideoFileClip(path)
            fbs = clip.reader.fps
            nframes = clip.reader.nframes
            duration = clip.duration
            max_duration=int(duration)+1
            frame_at_second = 1
            frame = clip.get_frame(frame_at_second)
            thumbnail = Image.fromarray(frame)
            file_name = file_name.split(".")[0]
            path = (os.path.abspath(__file__)).split("api")[0] + "media/upload-media/"
            thumbnail.save("{}{}_thumbnail.jpeg".format(path, file_name))
            instance.thumbnail = "upload-media/{}_thumbnail.jpeg".format(file_name)
            instance.save()
        except Exception as e:
            print("exception: ", e)
            instance.thumbnail = "upload-media/blank_image_thumbnail.jpeg".format(file_name)
            instance.save()
        
        
    
    def update_image_name(self, instance):
        # update uploaded image name
        image_url = str(instance.media_file)
        image_name = image_url.replace ('upload-media/', '')
        return image_name
        # instance.profile_image_name = image_name
        # instance.save ()