from django.urls import path, include
from rest_framework.routers import DefaultRouter

from api.payments.views import CreditCardViewSet

routers = DefaultRouter()

routers.register('credit-card', CreditCardViewSet, basename='credit-card')

urlpatterns = [
    path('', include(routers.urls))
]
