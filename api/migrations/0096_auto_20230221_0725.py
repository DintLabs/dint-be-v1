# Generated by Django 2.2 on 2023-02-21 07:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0095_postspayment_status_success'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userbankaccounts',
            name='country',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='userbankaccounts',
            name='postCode',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]