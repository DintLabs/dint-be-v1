# Generated by Django 2.2 on 2023-02-07 10:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0081_auto_20230206_0806'),
    ]

    operations = [
        migrations.AddField(
            model_name='useridentity',
            name='ip_address',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
    ]