# Generated by Django 2.2 on 2023-02-21 06:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0094_auto_20230221_0602'),
    ]

    operations = [
        migrations.AddField(
            model_name='postspayment',
            name='status_success',
            field=models.BooleanField(default=False),
        ),
    ]
