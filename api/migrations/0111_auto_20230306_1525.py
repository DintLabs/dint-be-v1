# Generated by Django 2.2 on 2023-03-06 15:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0110_auto_20230303_1536'),
    ]

    operations = [
        migrations.AddField(
            model_name='historicalmessages',
            name='media',
            field=models.URLField(blank=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='historicalmessages',
            name='type',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='messages',
            name='media',
            field=models.URLField(blank=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='messages',
            name='type',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
