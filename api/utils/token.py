from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six
from api.models.userModel import User

class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        user_obj = User.objects.get(id = user)
        return (
            six.text_type(user) + six.text_type(timestamp) +
            six.text_type(user_obj.is_active)
        )
account_activation_token = TokenGenerator()