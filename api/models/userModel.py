from __future__ import unicode_literals
from django.db import models
from django.utils import timezone
from django.db import transaction
from .roleModel import *
from simple_history.models import HistoricalRecords
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)

from django.conf import settings
from .UploadMediaModel import UploadMedia
from django.contrib.postgres.fields import JSONField

# from django.contrib.auth.models import User as UserModel


class UserManager(BaseUserManager):

    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email,and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        try:
            with transaction.atomic():
                user = self.model(email=email, **extra_fields)
                user.set_password(password)
                user.save(using=self._db)
                return user
        except:
            raise

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self._create_user(email, password=password, **extra_fields)

class Language(models.Model):
   name = models.CharField(max_length=255)

class User(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.
 
    """
    # id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=True, null=True)
    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    email = models.EmailField(max_length=254, blank=True, null=True, unique=True)
    email_verified_at = models.DateTimeField(blank=True, null=True)
    password = models.CharField(max_length=254, blank=True, null=True)
    remember_token = models.CharField(max_length=254, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    phone_no = models.CharField(max_length=17, help_text='Contact phone number', null=True, blank=True)
    desription = models.TextField(null=True, blank=True)
    fire_base_auth_key = models.CharField(max_length=250, null=True, blank=True)
    referral_id = models.CharField(max_length=30, null=True, blank=True)
    wallet_address = models.BinaryField(null = True, blank=True)
    wallet_private_key = models.BinaryField(null=True, blank=True)
    custom_username = models.CharField(max_length=50, blank=True, null=True)
    display_name = models.CharField(max_length=40, blank=True, null=True)
    bio = models.CharField(max_length=1000, blank=True, null=True)
    location = models.CharField(max_length=64, blank=True, null=True)
    website_url = models.CharField(max_length=100, blank=True, null=True)
    amazon_wishlist = models.CharField(max_length=100, blank=True, null=True)
    profile_image = models.URLField(max_length = 500, null=True, blank=True)
    banner_image = models.URLField(max_length = 500, null=True, blank=True)
    city = models.CharField(max_length=1000, blank=True, null=True)
    twitter = models.CharField(max_length=1000, blank=True, null=True)
    instagram = models.CharField(max_length=1000, blank=True, null=True)
    discord = models.CharField(max_length=1000, blank=True, null=True)
    is_private = models.BooleanField(default=False)
    able_to_be_found = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)
    otp_varification = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_send_time = models.DateTimeField(blank=True, null=True)
    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
    history = HistoricalRecords(table_name='user_history')
    is_active = models.BooleanField(default=True)
    is_online = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    connections = models.IntegerField(default=0)
    email_token = models.CharField(max_length=255, null=True, blank=True)
    email_token_valid = models.DateTimeField(blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)

    class Meta:
        db_table = 'auth_user'
        indexes = [
            models.Index(fields=['id', 'first_name', 'last_name', 'email', 'is_active'])
        ]

class UserPreferences(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    enable_push_notification = models.BooleanField(default=False)
    enable_email_notification = models.BooleanField(default=False)
    show_full_text = models.BooleanField(default=False)
    monthly_news_letter = models.BooleanField(default=False)
    new_posts_summary = models.BooleanField(default=False)
    new_posts_summary_time = models.IntegerField(blank=True, null=True)
    new_stream = models.BooleanField(default=False)
    upcoming_stream_reminder = models.BooleanField(default=False)
    new_private_msg_summary = models.BooleanField(default=False)
    new_private_msg_summary_time = models.IntegerField(blank=True, null=True)
    receive_less_notification = models.BooleanField(default=False)
    subscription_notification = models.BooleanField(default=False)
    new_comment = models.BooleanField(default=False)
    new_like = models.BooleanField(default=False)
    language = models.ForeignKey(Language,on_delete=models.DO_NOTHING, null=True)
   

class UserReferralWallet(models.Model):
    referred_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='referred_by' )
    user_referral = models.ForeignKey(User, on_delete=models.CASCADE, related_name='referred_to')
    wallet = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class ConfineUsers(models.Model):
    USER_BLOCK_TYPE = (
        ('block', 'block'),
        ('restrict', 'restrict'),
        ('none', 'none')
    )
    main_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="main_user")
    confine_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="confine_user")
    user_block_type = models.CharField(max_length=16, choices=USER_BLOCK_TYPE, default='none')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class UserCustomLists(models.Model):
    name = models.CharField(max_length=32)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class UserCustomGroupMembers(models.Model):
    user_custom_lists = models.ForeignKey(UserCustomLists, on_delete=models.CASCADE)
    member = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class UserCloseFriends(models.Model):
    main_user = models.ForeignKey(User, on_delete=models.CASCADE) 
    close_friend = models.ForeignKey(User, on_delete=models.CASCADE, related_name="close_friend")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class UserIdentity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    fullname = models.CharField(max_length=255, blank=True, null=True)
    gender = models.CharField(max_length=6, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    documentNumber = models.CharField(max_length=255, blank=True, null=True)
    document_type = models.CharField(max_length=20, blank=True, null=True)
    nationality = models.CharField(max_length=50, blank=True, null=True)
   
    verified = models.BooleanField(default=False)

    class Meta:
        db_table = 'user_identity'
        indexes = [
            models.Index(fields=['id'])
        ]
