from api.models.messageNotificationModel import *
from api.services.user import userService
from datetime import timedelta, datetime
from apscheduler.schedulers.background import BackgroundScheduler


def start(self, request, prefhours, d):
     #print(d)
     for i in d:
        start_date =d[i]
        #end_date = start_date + timedelta(hours=prefhours)
        scheduler = BackgroundScheduler()
        scheduler.add_job(userService.UserService.schedule_api, trigger='interval', hours=prefhours, start_date=start_date, args=[self, request, i] )
        scheduler.start()

