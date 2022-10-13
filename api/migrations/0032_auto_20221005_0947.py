# Generated by Django 2.2 on 2022-10-05 09:47

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0031_creditcard_card_number'),
    ]

    operations = [
        migrations.AlterField(
            model_name='creditcard',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
