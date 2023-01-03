# Generated by Django 2.2 on 2022-12-30 07:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0072_auto_20221230_0655'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='historicaluser',
            name='wallet_privatekey',
        ),
        migrations.RemoveField(
            model_name='user',
            name='wallet_privatekey',
        ),
        migrations.AddField(
            model_name='historicaluser',
            name='wallet_private_key',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='wallet_private_key',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]