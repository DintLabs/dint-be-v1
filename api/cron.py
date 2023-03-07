from django_cron import CronJobBase, Schedule
from api.serializers.stories import *
import datetime
import requests
from datetime import date, timedelta
from django.utils import timezone
from api.models.userModel import *
from api.models.UserStoriesModel import UserStoriesLikes, UserStories
import pytz
from django.core.management.base import BaseCommand
import redis
from dint.settings import *
from django.db.models import Q
from api.utils.getwallet import getWallet
from dint import settings
from cryptography.fernet import Fernet

class MyCronJob(CronJobBase):
    RUN_EVERY_MINS = 1 

    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'api.my_cron_job'    

    def do(self):
        print("success")
        # print(requests.user.id)
        try:
            tz = pytz.timezone('Asia/Kolkata')
            current_time = datetime.datetime.now(tz)
            all_stories = UserStories.objects.filter(expiration_time__lt = current_time).update(is_archived = True)
            
            # wallet_obj = User.objects.filter(wal)
            user_wallet = list(User.objects.values_list("wallet_address", flat=True).exclude(wallet_address__isnull=True))
            for i in user_wallet:
               
                user_wallet = i.tobytes()
                # if (i !=None):
                try:
                   
                    key = Fernet(settings.ENCRYPTION_KEY)
                    user_decwallet = key.decrypt(user_wallet).decode()
                    user_address = user_decwallet
                    balance = getWallet(user_address)
                    user = User.objects.get(wallet_address = user_wallet)
                    user_id = user.id
                    r = redis.Redis(host=REDIS_HOST,port=REDIS_PORT)
                    balance_key = r.set("balance_key" , user_id)
                    balance_value = r.set("balance_value", balance)
                    get_key = r.get("balance_key")
                    get_value = r.get("balance_value")
                    user_obj = get_key.decode('UTF-8')  
                    blnc_obj = get_value.decode('UTF-8')  
                    update_balance = User.objects.filter(id = user_obj).update(user_wallet_balance=blnc_obj)
                except Exception as e:
                    pass
        except Exception as e:
            print(e)
