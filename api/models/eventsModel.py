from operator import mod
from statistics import mode
from django.db import models
from django.utils import timezone
from api.models.venueModel import Venue
from simple_history.models import HistoricalRecords
from .userModel import User


class Events(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_events', on_delete=models.DO_NOTHING, null=True, blank=True)
    eventFequency = models.CharField(max_length=50, null=True, blank=True)
    balanceFrequency = models.CharField(max_length=50, null=True, blank=True)
    eventDate = models.DateField(default=timezone.now)
    eventDescription = models.CharField(max_length=50, null=True, blank=True)
    eventEndTime = models.TimeField(null=True, blank=True)
    eventId = models.IntegerField(null=True, blank=True)
    eventName = models.CharField(max_length=50, null=True, blank=True)
    eventPhoto = models.URLField(max_length = 500, null=True, blank=True)
    eventstartTime = models.TimeField(null=True, blank=True)
    eventDateCreated = models.DateField(default=timezone.now)
    network = models.CharField(max_length=50, null=True, blank=True)
    tokenDecimal = models.CharField(max_length=50, null=True, blank=True)
    tokenIcon = models.CharField(max_length=50, null=True, blank=True)
    tokenName = models.CharField(max_length=50, null=True, blank=True)
    tokenSymbol = models.CharField(max_length=50, null=True, blank=True)
    tokenType = models.CharField(max_length=50, null=True, blank=True)
    tokenAddress = models.CharField(max_length=50, null=True, blank=True)
    valueName = models.CharField(max_length=50, null=True, blank=True)
    venue = models.ForeignKey(Venue, null=True, blank=True, on_delete=models.DO_NOTHING)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='events_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'events'
        indexes = [
            models.Index(fields=['id'])
        ]
