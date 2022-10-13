from datetime import datetime, timedelta
from api.models.UserSubscriptionModel import UserSubscription
from api.models.userSubscriptionTierModel import UserSubscriptionTier
from api.serializers.subscription import *
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.postMessages import *
from api.utils.messages.subscriptionMessages import *
from api.serializers.page import GetPageSubscriptionSerializer
from .subscriptionBaseService import SubscriptionBaseService


class SubscriptionService(SubscriptionBaseService):
    """
    Create, Retrieve, Update or Delete a Tier instance and Return all Tier.
    """

    def __init__(self):
        pass

    def get_tier_by_user(self, request, format=None):
        """
        Retun all the Tiers by User ID.
        """
        sub_obj = UserSubscriptionTier.objects.filter(user = request.user.id)
        serializer = GetSubscriptionTierSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def create_tier(self, request, format=None):
        """
        Create New Tier. 
        """
        serializer = CreateUpdateSubscriptionTierSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": POST_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_tier(self, request, pk, format=None):
        """
        Delete Tier. 
        """
        try:
            sub_obj = UserSubscriptionTier.objects.get(id = pk)
        except UserSubscriptionTier.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        sub_obj.delete ()
        return ({"code": status.HTTP_200_OK, "message": POST_DELETED})

    def update_tier(self, request, pk, format=None):
        """
        Updates Post
        """
        data = request.data
        try:
            sub_obj = UserSubscriptionTier.objects.get(id = pk)
        except UserSubscriptionTier.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = CreateUpdateSubscriptionTierSerializer(sub_obj, data=data)
        if serializer.is_valid ():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_tier_by_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            sub_obj = UserSubscriptionTier.objects.get(id = pk)
        except UserSubscriptionTier.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        serializer = GetSubscriptionTierSerializer(sub_obj)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def subscribe(self, request, format=None):
        """
        Create New Tier. 
        """
        serializer = CreateUpdateSubscriptionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": POST_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})


    def cancel_subscription(self, request,pk, format=None):
        """
        Cancel Subscription
        """

        try:
            sub_obj = UserSubscription.objects.get(id = pk)
        except UserSubscription.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        sub_obj.is_active = False
        sub_obj.reject_reason = request.data['reject_reason']
        sub_obj.save()
        return ({"data": None, "code": status.HTTP_200_OK, "message": POST_FETCHED})

    def get_active_subscriptions_by_token(self, request, format=None):
        sub_obj = UserSubscription.objects.filter(user = request.user.id, is_active = True)
        serializer = GetSubscriptionSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})
    
    def get_all_subscriptions_by_token(self, request, format=None):
        sub_obj = UserSubscription.objects.filter(user = request.user.id)
        serializer = GetSubscriptionSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": POST_FETCHED})
        

    def get_campaign_by_user(self, request, format=None):
        """
        Retun all the Tiers by User ID.
        """
        sub_obj = PromotionCampaign.objects.filter(user = request.user.id)
        serializer = GetPromotionCampaignSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": CAMPAIGN_FETCHED})

    def create_campaign(self, request, format=None):
        """
        Create New campaign. 
        """
        try:
            existing_campaign_obj = PromotionCampaign.objects.filter(page = request.data['page']).latest('created_at')
            exipiration_date = existing_campaign_obj.created_at + timedelta(days = int(existing_campaign_obj.offer_expiration_in_days))
            if existing_campaign_obj.offer_expiration_in_days is None:
                return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "You already have an active promotion campaign with No Expitation Limit!"})
            elif  exipiration_date > timezone.now():
                return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "You already have an active promotion campaign"})
        except:
            pass

        serializer = CreateUpdatePromotionCampaignSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": CAMPAIGN_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_campaign(self, request, pk, format=None):
        """
        Delete campaign. 
        """
        try:
            sub_obj = PromotionCampaign.objects.get(id = pk)
        except PromotionCampaign.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        sub_obj.delete ()
        return ({"code": status.HTTP_200_OK, "message": CAMPAIGN_DELETED})

    def update_campaign(self, request, pk, format=None):
        """
        Updates Post
        """
        data = request.data
        try:
            sub_obj = PromotionCampaign.objects.get(id = pk)
        except PromotionCampaign.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = CreateUpdatePromotionCampaignSerializer(sub_obj, data=data)
        if serializer.is_valid ():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": CAMPAIGN_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_campaign_by_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            sub_obj = PromotionCampaign.objects.get(id = pk)
        except PromotionCampaign.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        serializer = GetPromotionCampaignSerializer(sub_obj)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": CAMPAIGN_FETCHED})


    def get_free_trial_by_user(self, request, format=None):
        """
        Retun all the Tiers by User ID.
        """
        sub_obj = FreeTrial.objects.filter(user = request.user.id)
        serializer = GetFreeTrialSerializer(sub_obj, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": FREE_TRIAL_FETCHED})

    def create_free_trial(self, request, format=None):
        """
        Create New campaign. 
        """

        try:
            existing_free_trial_obj = FreeTrial.objects.filter(page = request.data['page']).latest('created_at')
            exipiration_date = existing_free_trial_obj.created_at + timedelta(days = int(existing_free_trial_obj.offer_expiration))
            if existing_free_trial_obj.offer_expiration is None:
                return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "You already have an active Free Trial with No Expitation Limit!"})
            if  exipiration_date > timezone.now():
                return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": "You already have an active Free Trial"})
        except:
            pass

        serializer = CreateUpdateFreeTrialSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": FREE_TRIAL_CREATED})
        return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    def delete_free_trial(self, request, pk, format=None):
        """
        Delete campaign. 
        """
        try:
            sub_obj = FreeTrial.objects.get(id = pk)
        except FreeTrial.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        sub_obj.delete ()
        return ({"code": status.HTTP_200_OK, "message": FREE_TRIAL_DELETED})

    def update_free_trial(self, request, pk, format=None):
        """
        Updates Post
        """
        data = request.data
        try:
            sub_obj = FreeTrial.objects.get(id = pk)
        except FreeTrial.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

        serializer = CreateUpdateFreeTrialSerializer(sub_obj, data=data)
        if serializer.is_valid ():
            serializer.save ()
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": FREE_TRIAL_UPDATED})
        else:
            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
     
    def get_free_trial_by_id(self, request, pk, format=None):
        """
        Retrieve a Post by ID
        """
        try:
            sub_obj = FreeTrial.objects.get(id = pk)
        except FreeTrial.DoesNotExist:
            return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
        serializer = GetFreeTrialSerializer(sub_obj)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": FREE_TRIAL_FETCHED})

    def get_subscribers_by_page_id(self, request, pk, format=None):
        data = {}
        
        # Fetching Active Subscription on page.

        parent_obj = UserSubscription.objects.filter(page = pk)

        data['all_subscriptions'] = GetPageSubscriptionSerializer(parent_obj, many=True).data

        active_sub_obj = parent_obj.filter(page = pk, end_date__lte = timezone.now())
        data['active_subscriptions'] = GetPageSubscriptionSerializer(active_sub_obj, many=True).data

        # Fetching Expired Subscription on Page

        expired_sub_obj = parent_obj.filter(page = pk, end_date__gt = timezone.now())
        data['expired_subscriptions'] = GetPageSubscriptionSerializer(expired_sub_obj, many=True).data

        return ({"data": data, "code": status.HTTP_200_OK, "message": "Subscribers Fetched Successfully. "})

    def get_pages_by_subscriber_id(self, request, pk, format=None):
        data = {}
        
        # Fetching Active Subscription on page.

        parent_obj = UserSubscription.objects.filter(user = pk)

        data['all_subscriptions'] = GetPageSubscriptionSerializer(parent_obj, many=True).data

        active_sub_obj = parent_obj.filter(page = pk, end_date__lte = timezone.now())
        data['active_subscriptions'] = GetPageSubscriptionSerializer(active_sub_obj, many=True).data

        # Fetching Expired Subscription on Page

        expired_sub_obj = parent_obj.filter(page = pk, end_date__gt = timezone.now())
        data['expired_subscriptions'] = GetPageSubscriptionSerializer(expired_sub_obj, many=True).data

        return ({"data": data, "code": status.HTTP_200_OK, "message": "Pages Fetched Successfully. "})

        
        
