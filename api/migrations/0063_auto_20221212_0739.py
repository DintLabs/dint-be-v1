# Generated by Django 2.2 on 2022-12-12 07:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0062_userbookaccounts_primary'),
    ]

    operations = [
        migrations.CreateModel(
            name='TransferWiseDetails',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_id', models.IntegerField()),
                ('account_holder_name', models.CharField(max_length=255)),
                ('account_number', models.CharField(blank=True, max_length=255, null=True)),
                ('abrotn', models.IntegerField()),
                ('city', models.CharField(blank=True, max_length=255, null=True)),
                ('postcode', models.IntegerField()),
                ('first_line', models.CharField(max_length=255)),
                ('primary', models.BooleanField(default=False)),
            ],
        ),
        migrations.DeleteModel(
            name='UserBookaccounts',
        ),
    ]
