from django_cron import CronJobBase, Schedule
from api.serializers.stories import *
import datetime

from datetime import date, timedelta
from django.utils import timezone
from api.models.UserStoriesModel import UserStoriesLikes, UserStories
import pytz

class MyCronJob(CronJobBase):
    RUN_EVERY_MINS = 1 

    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'api.my_cron_job'    

    def do(self):
    
        try:
            tz = pytz.timezone('Asia/Kolkata')
            current_time = datetime.datetime.now(tz)
            all_stories = UserStories.objects.filter(expiration_time__lt = current_time).update(is_archived = True)
           
        except Exception as e:
            print(e)