# Generated by Django 2.2 on 2022-10-19 10:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0050_auto_20221019_0909'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userpreferences',
            name='discount_from_users',
        ),
        migrations.AlterField(
            model_name='userpreferences',
            name='new_comment',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='userpreferences',
            name='new_like',
            field=models.BooleanField(default=False),
        ),
    ]
