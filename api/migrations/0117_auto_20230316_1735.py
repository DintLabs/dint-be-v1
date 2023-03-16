# Generated by Django 2.2 on 2023-03-16 17:35

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0116_auto_20230316_1559'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='user_referred_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
