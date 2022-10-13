from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from rest_framework.viewsets import ModelViewSet

from api.models import UserTipReference
from api.serializers.subscription import UserTipReferenceModelSerializer
from api.services.subscription import SubscriptionService

subscriptionService = SubscriptionService()



class ListCreateUpdateDeleteSubscriptionTierView(APIView):

    def get(self, request, format=None):
        """
        Return all the Subscription Tier.
        """
        result = subscriptionService.get_tier_by_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Subscription Tier. 
        """
        result = subscriptionService.create_tier(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Subscription Tier.
        """
        result = subscriptionService.update_tier(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Subscription Tier. 
        """
        result = subscriptionService.delete_tier(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class GetSubscriptionTierView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = subscriptionService.get_tier_by_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class SubscriptionView(APIView):

    def get(self, request, format=None):
        """
        Retun all the Subscription.
        """
        result = subscriptionService.get_active_subscriptions_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Subscribe
        """
        result = subscriptionService.subscribe(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request,pk, format=None):
        """
        Cancel Subscription
        """
        result = subscriptionService.cancel_subscription(request,pk,format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetActiveSubscriptionView(APIView):

    
    def get(self, request, format=None):
        """
        Retun all the Subscription.
        """
        result = subscriptionService.get_all_subscriptions_by_token(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class ListCreateUpdateDeletePromotionCampaignView(APIView):

    def get(self, request, format=None):
        """
        Return all the Subscription Tier.
        """
        result = subscriptionService.get_campaign_by_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Subscription Tier. 
        """
        result = subscriptionService.create_campaign(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Subscription Tier.
        """
        result = subscriptionService.update_campaign(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Subscription Tier. 
        """
        result = subscriptionService.delete_campaign(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class GetPromotionCampaignView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = subscriptionService.get_campaign_by_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class ListCreateUpdateDeleteFreeTrialView(APIView):

    def get(self, request, format=None):
        """
        Return all the Free Trials.
        """
        result = subscriptionService.get_free_trial_by_user(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Free Trials. 
        """
        result = subscriptionService.create_free_trial(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Free Trials.
        """
        result = subscriptionService.update_free_trial(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Free Trials. 
        """
        result = subscriptionService.delete_free_trial(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class GetFreeTrialView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Free Trial by ID
        """
        result = subscriptionService.get_free_trial_by_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetSubscribersByPageView(APIView):

    def post(self, request, pk, format=None):
        """
        Retrieve Subscriber By Page ID
        """
        result = subscriptionService.get_subscribers_by_page_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    

class GetPageBySubscriberIDView(APIView):

    def post(self, request, pk, format=None):
        """
        Retrieve Subscriber By Page ID
        """
        result = subscriptionService.get_pages_by_subscriber_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class UserTipReferenceModelViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, ]
    serializer_class = UserTipReferenceModelSerializer
    queryset = UserTipReference.objects.all()

    def get_queryset(self):
        return UserTipReference.objects.filter(from_user=self.request.user)

