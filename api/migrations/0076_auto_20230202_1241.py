# Generated by Django 2.2 on 2023-02-02 12:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0075_auto_20230202_1221'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='historicaluser',
            name='status',
        ),
        migrations.RemoveField(
            model_name='user',
            name='status',
        ),
        migrations.AddField(
            model_name='historicaluser',
            name='connections',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='connections',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]