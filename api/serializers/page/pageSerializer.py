from math import exp
from api.models.UserSubscriptionModel import UserSubscription
from api.models.campaignModel import PromotionCampaign
from api.models.freeSubscriptionTrialModel import FreeTrial
from api.models.userSubscriptionTierModel import UserSubscriptionTier
from api.serializers.subscription.subscriptionSerializer import  GetSubscriptionTierSerializer
from api.serializers.user.userSerializer import GetUserPageSerializer
from rest_framework import serializers
from api.models.pageModel import Page
from api.serializers.user import UserLoginDetailSerializer
from datetime import timedelta
from dateutil.relativedelta import relativedelta
from api.services.subscription.subscriptionService import timezone


class CreateUpdatePageSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Page
        fields = '__all__'



class GetPagePromotionCampaignSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    page = GetSubscriptionTierSerializer()

    class Meta(object):
        model = PromotionCampaign
        fields = '__all__'

class GetPageSubscriptionTierSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """

    discount_price = serializers.SerializerMethodField()

    class Meta(object):
        model = UserSubscriptionTier
        fields = '__all__'

    def get_discount_price(self, obj):
        try:
            return (obj.page.subscribe_amount - ( float(obj.page.subscribe_amount/100) * float(obj.discount) )) * int(obj.validity_in_months)
        except:
            return None

class GetPageFreeTrialSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    page = GetSubscriptionTierSerializer()

    class Meta(object):
        model = FreeTrial
        fields = '__all__'

class GetUserPageWithTierSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """

    subscription_tier_page = GetPageSubscriptionTierSerializer(many=True)
    class Meta(object):
        model = Page
        fields = '__all__'

class GetPageSubscriptionSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    subscription_tier = GetSubscriptionTierSerializer()
    promotion_campaign = GetPagePromotionCampaignSerializer()
    free_trial = GetPageFreeTrialSerializer()
    expiration_date = serializers.SerializerMethodField()
    total_amount = serializers.SerializerMethodField()
    user_subscription_ends_on = serializers.SerializerMethodField()
    user = UserLoginDetailSerializer()
    page = GetUserPageWithTierSerializer()
    total_duration = serializers.SerializerMethodField()

    class Meta(object):
        model = UserSubscription
        fields = '__all__'
    
    def get_expiration_date(self, obj):
        if obj.subscription_tier is not None:
            expiry_date = obj.created_at + relativedelta(months = int(obj.subscription_tier.validity_in_months))
            return expiry_date
        elif obj.promotion_campaign is not None:
            expiry_date = obj.created_at + relativedelta(days = int(obj.promotion_campaign.offer_expiration_in_days))
            return expiry_date
        elif obj.free_trial is not None:
            expiry_date = obj.created_at + relativedelta(days = int(obj.free_trial.offer_expiration))
            return expiry_date
        else:
            expiry_date = obj.created_at + relativedelta(months = int(1))
            return expiry_date

    def get_total_amount(self, obj):
        if obj.subscription_tier is not None:
            try:
                return obj.page.subscribe_amount - ( float(obj.page.subscribe_amount/100) * float(obj.subscription_tier.discount) )
            except: 
                return None

        elif obj.promotion_campaign is not None:
            try:
                return obj.page.subscribe_amount - ( float(obj.page.subscribe_amount/100) * float(obj.promotion_campaign.discount_percentage) )
            except:
                None
        elif obj.free_trial is not None:
            return 0
        else:
            return obj.page.subscribe_amount

    def get_user_subscription_ends_on(self, obj):
        if obj.subscription_tier is not None:
            expiry_date = obj.created_at + relativedelta(months = int(obj.subscription_tier.validity_in_months))
            return expiry_date
        elif obj.promotion_campaign is not None:
            expiry_date = obj.created_at + relativedelta(days = int(31))
            return expiry_date
        elif obj.free_trial is not None:
            expiry_date = obj.created_at + relativedelta(days = int(obj.free_trial.trial_duration))
            return expiry_date
        else:
            expiry_date = obj.created_at + relativedelta(months = int(1))
            return expiry_date

    def get_total_duration(self, obj):
        duration_in_days = (timezone.now() -  obj.created_at).days
        return duration_in_days
        
class GetPageSerializer(serializers.ModelSerializer):
    """
    This is for Get
    """
    subscription_tier_page = GetPageSubscriptionTierSerializer(many=True)
    page_subscription = serializers.SerializerMethodField()
    campaign_page = serializers.SerializerMethodField()
    trial_page = serializers.SerializerMethodField()
    user = UserLoginDetailSerializer()
    is_subscribed = serializers.SerializerMethodField()
    class Meta(object):
        model = Page
        fields = '__all__'


    def get_page_subscription(self, obj):
        user_id = self.context.get('user_id')
        if user_id:
            try:
                res_obj = UserSubscription.objects.get(user=user_id, page = obj.id, is_active = True)
                return [GetPageSubscriptionSerializer(res_obj).data]
            except UserSubscription.DoesNotExist:
                return []
        else:
            return []

    def get_is_subscribed(self, obj):
        user_id = self.context.get('user_id')
        if user_id:
            try:
                res_obj = UserSubscription.objects.get(user=user_id, page = obj.id, is_active = True)
                return True
            except UserSubscription.DoesNotExist:
                return False
        else:
            return False
    

    def get_campaign_page(self, obj):
        try:
            existing_campaign_obj = PromotionCampaign.objects.filter(page = obj.id).latest('created_at')
            exipiration_date = existing_campaign_obj.created_at + timedelta(days = int(existing_campaign_obj.offer_expiration_in_days))
            if existing_campaign_obj.offer_expiration_in_days is None or exipiration_date > timezone.now():
                res = GetPagePromotionCampaignSerializer(existing_campaign_obj).data
                res['expiration_date'] = exipiration_date

                #Fetching Number of Subscribers.
                sub_count = UserSubscription.objects.filter(promotion_campaign = existing_campaign_obj.id, is_active = True).count()
                res['offer_limit_left'] = res['offer_limit'] -  sub_count

                #Fetching discounted price
                res['discount_price'] = existing_campaign_obj.page.subscribe_amount - ( (existing_campaign_obj.page.subscribe_amount/100) * res['discount_percentage'] )
                return [res]
            else:
                return []
        except:
            return []

    def get_trial_page(self, obj):
        try:
            existing_free_trial_obj = FreeTrial.objects.filter(page = obj.id).latest('created_at')
            exipiration_date = existing_free_trial_obj.created_at + timedelta(days = int(existing_free_trial_obj.offer_expiration))
            if existing_free_trial_obj.offer_expiration is None or exipiration_date > timezone.now():
                res = GetPageFreeTrialSerializer(existing_free_trial_obj).data
                res['expiration_date'] = exipiration_date

                #Fetching Number of Subscribers.
                sub_count = UserSubscription.objects.filter(free_trial = existing_free_trial_obj.id, is_active = True).count()
                res['offer_limit_left'] = res['offer_limit'] -  sub_count
                return [res]    
            else:
                return []
        except:
            return []

    

  