# Generated by Django 2.2 on 2022-12-28 09:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0069_auto_20221213_0746'),
    ]

    operations = [
        migrations.AddField(
            model_name='historicaluser',
            name='wallet_address',
            field=models.CharField(blank=True, max_length=300, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='wallet_address',
            field=models.CharField(blank=True, max_length=300, null=True),
        ),
    ]
