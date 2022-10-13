from operator import mod
from statistics import mode
from turtle import title
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords
from .userModel import User



class Page(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, related_name='user_page', on_delete=models.CASCADE, null=True, blank=True)
    page_name = models.CharField(max_length=30, null=True, blank=True)
    title = models.CharField(max_length=80, null=True,blank=True)
    desciption = models.CharField(max_length=80, null=True,blank=True) 
    type = models.CharField(max_length=80, null=True,blank=True)
    profile_picture = models.URLField(max_length=1000, null=True, blank=True)
    cover_picture = models.URLField(max_length=1000, null=True, blank=True)
    subscribe_amount = models.FloatField(null=True, blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    history = HistoricalRecords(table_name='page_history')
    can_delete = models.BooleanField(default=True)

    def __unicode__(self):
        return self.id

    class Meta:
        db_table = 'page'
        indexes = [
            models.Index(fields=['id'])
        ]
