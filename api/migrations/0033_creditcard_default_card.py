# Generated by Django 2.2 on 2022-10-05 10:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0032_auto_20221005_0947'),
    ]

    operations = [
        migrations.AddField(
            model_name='creditcard',
            name='default_card',
            field=models.BooleanField(default=False),
        ),
    ]
