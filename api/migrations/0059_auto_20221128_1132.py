# Generated by Django 2.2 on 2022-11-28 11:32

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0058_auto_20221128_1010'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userclosefriends',
            name='main_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
