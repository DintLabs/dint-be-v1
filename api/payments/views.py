from django.conf import settings
from django.shortcuts import render
import stripe
from rest_framework import status
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet, ModelViewSet
from rest_framework.permissions import IsAuthenticated

from api.payments.models import CreditCard
from api.payments.serializers import CreditCardModelSerializer, CreditCardSerializer
from api.payments.utils import add_card

stripe.api_key = settings.STRIPE_API_KEY


# Create your views here.


class CreditCardViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = CreditCardModelSerializer
    queryset = CreditCard.objects.all()

    def get_queryset(self):
        return CreditCard.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        try:
            serializer = CreditCardSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            card_token, card_id, card_type = add_card(serializer.validated_data)
            customer = stripe.Customer.create(
                name=serializer.validated_data['email'],
                source=card_token,
                email=serializer.validated_data['email'],
            )

            credit_card = CreditCard(
                country=serializer.validated_data['country'],
                state=serializer.validated_data['state'],
                street=serializer.validated_data['street'],
                city=serializer.validated_data['city'],
                zip_code=serializer.validated_data['zip_code'],
                email=serializer.validated_data['email'],
                card_name=serializer.validated_data['card_name'],
                card_expired=str(serializer.validated_data['exp_month']) + '/' + str(serializer.validated_data['exp_year']),
                card_number=serializer.validated_data['card_number'][-4:],
                card_token=card_token,
                customer_id=customer.id,
                card_id=card_id,
                user=request.user,
                card_type=card_type
            )
            credit_card.save()
            credit_cards = CreditCard.objects.filter(user=request.user)
            serializer = self.serializer_class(credit_cards, many=True)
            return Response({"cards": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": e.args[0]}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        stripe.Customer.delete_source(
            instance.customer_id,
            instance.card_id,
        )
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
