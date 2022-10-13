from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User


class Venue(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_venues', on_delete=models.DO_NOTHING, null=True, blank=True)
    venueAddress = models.CharField(max_length=500, null=True, blank=True)
    venueGmap = models.CharField(max_length=500, null=True, blank=True)
    venueName = models.CharField(max_length=500, null=True, blank=True)
    venuedataCreated = models.DateField(default=timezone.now)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='venue_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'venue'
        indexes = [
            models.Index(fields=['id'])
        ]
