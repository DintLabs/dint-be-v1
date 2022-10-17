from abc import ABC, abstractmethod


class UploadMediaBaseService(ABC):

    @abstractmethod
    def create_upload_media(self):
        """ Abstract method to upload media """
        pass