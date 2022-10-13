from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords


class UploadMedia(models.Model):
    id = models.AutoField(primary_key=True)
    media_file_url = models.CharField(max_length=255, blank=True, null=True)
    media_file_name = models.CharField(max_length=250, blank=True, null=True)
    thumbnail = models.ImageField(upload_to='upload-media/', blank=True, null=True)
    thumbnail_url = models.CharField(max_length=255, blank=True, null=True)
    file_type = models.CharField(max_length=120, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='upload_media_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'upload_media'
        indexes = [
            models.Index(fields=['id'])
        ]
