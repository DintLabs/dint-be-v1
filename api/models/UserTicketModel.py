from django.db import models
from .userModel import User
from .eventsModel import Events

class UserTickets(models.Model):
    id = models.AutoField(primary_key=True)
    authId = models.CharField(max_length = 200, null=True, blank=True)
    userId = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    eventId = models.ForeignKey(Events, on_delete=models.CASCADE, null=True, blank=True)

    def __unicode__(self):
        return self.id
    
    class Meta:
        db_table = 'UserTickets'
    
