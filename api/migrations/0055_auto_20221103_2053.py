# Generated by Django 2.2 on 2022-11-03 20:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0054_auto_20221103_2043'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='historicaluploadmedia',
            name='media_file_url',
        ),
        migrations.RemoveField(
            model_name='uploadmedia',
            name='media_file_url',
        ),
    ]