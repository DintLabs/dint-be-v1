# Generated by Django 2.2 on 2023-01-31 09:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0078_useridentity_documentnumber'),
    ]

    operations = [
        migrations.AlterField(
            model_name='useridentity',
            name='date_of_birth',
            field=models.DateField(blank=True, null=True),
        ),
    ]