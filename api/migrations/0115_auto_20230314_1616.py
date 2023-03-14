# Generated by Django 2.2 on 2023-03-14 16:16

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0114_auto_20230314_1319'),
    ]

    operations = [
        migrations.AlterField(
            model_name='messages',
            name='chat_room',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='message_chat_room', to='api.ChatRoom'),
        ),
        migrations.AlterField(
            model_name='messages',
            name='reciever',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='reciever_user', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='messages',
            name='sender',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='sender_user', to=settings.AUTH_USER_MODEL),
        ),
    ]
