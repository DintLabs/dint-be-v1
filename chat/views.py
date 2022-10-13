from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
# Create your views here.
from django.shortcuts import render
# from .models import ChatMessages, Notifications
def index(request):
    return render(request, 'chat/index.html')

def room(request, room_name):
    return render(request, 'chat/room.html', {
        'room_name': room_name
    })
