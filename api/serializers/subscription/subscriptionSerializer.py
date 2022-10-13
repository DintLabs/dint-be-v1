from rest_framework import serializers
from api.models import *
from api.serializers.user import UserLoginDetailSerializer


class CreateUpdateSubscriptionTierSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = UserSubscriptionTier
        fields = '__all__'


class GetSubscriptionTierSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    user = UserLoginDetailSerializer()
    class Meta(object):
        model = UserSubscriptionTier
        fields = '__all__'


class CreateUpdateSubscriptionSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = UserSubscription
        fields = '__all__'





class CreateUpdatePromotionCampaignSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = PromotionCampaign
        fields = '__all__'


class GetPromotionCampaignSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    user = UserLoginDetailSerializer()
    page = GetSubscriptionTierSerializer()

    class Meta(object):
        model = PromotionCampaign
        fields = '__all__'

class CreateUpdateFreeTrialSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = FreeTrial
        fields = '__all__'


class GetFreeTrialSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    user = UserLoginDetailSerializer()
    page = GetSubscriptionTierSerializer()

    class Meta(object):
        model = FreeTrial
        fields = '__all__'
        
class GetSubscriptionSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    user = UserLoginDetailSerializer()
    subscription_tier = GetSubscriptionTierSerializer()
    promotion_campaign = GetPromotionCampaignSerializer()
    free_trial = GetFreeTrialSerializer()

    class Meta(object):
        model = UserSubscription
        fields = '__all__'


class UserTipReferenceModelSerializer(serializers.ModelSerializer):
    to_user_details = serializers.SerializerMethodField()
    from_user_details = serializers.SerializerMethodField()

    class Meta:
        model = UserTipReference
        exclude = ['created_at', 'updated_at']

    def get_to_user_details(self, obj):
        return {
            'name': obj.to_user.name,
            'email': obj.to_user.name,
        }

    def get_from_user_details(self, obj):
        return {
            'name': obj.from_user.name,
            'email': obj.from_user.name,
        }
