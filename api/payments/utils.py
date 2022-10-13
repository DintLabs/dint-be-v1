import requests
import stripe
from django.conf import settings

stripe.api_key = settings.STRIPE_API_KEY


def add_card(data):
    card = stripe.Token.create(
        card={
            "number": data["card_number"],
            "exp_month": data["exp_month"],
            "exp_year": data["exp_year"],
            "cvc": data["cvc"],
        },
    )

    return card['id'], card['card']['id'], card.card.brand
