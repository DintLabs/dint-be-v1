# Generated by Django 2.2 on 2023-03-03 15:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0109_auto_20230303_1116'),
    ]

    operations = [
        migrations.AddField(
            model_name='userstories',
            name='type',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='userstories',
            name='story',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
    ]
