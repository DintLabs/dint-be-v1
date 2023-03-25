from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0112_auto_20230307_1053'),
    ]

    operations = [
        migrations.AddField(
            model_name='historicalmessages',
            name='media',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='historicalmessages',
            name='type',
            field=models.CharField(max_length=50, null=True),
        ),

  
    ]
