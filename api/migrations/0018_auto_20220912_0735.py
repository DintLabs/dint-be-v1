# Generated by Django 2.2 on 2022-09-12 07:35

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import simple_history.models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0017_auto_20220908_0657'),
    ]

    operations = [
        migrations.CreateModel(
            name='PromotionCampaign',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('campaign_type', models.IntegerField(default=1, help_text='1. New User, 2. Expired Subscriber User 3. Both')),
                ('offer_limit', models.IntegerField(default=5)),
                ('offer_expiration_in_days', models.IntegerField(default=5)),
                ('discount_percentage', models.FloatField(blank=True, null=True)),
                ('message', models.CharField(blank=True, max_length=500, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('deleted_at', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('can_delete', models.BooleanField(default=True)),
                ('page', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='campaign_page', to='api.Page')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='campaign_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'promotion_campaign',
            },
        ),
        migrations.CreateModel(
            name='HistoricalPromotionCampaign',
            fields=[
                ('id', models.IntegerField(blank=True, db_index=True)),
                ('campaign_type', models.IntegerField(default=1, help_text='1. New User, 2. Expired Subscriber User 3. Both')),
                ('offer_limit', models.IntegerField(default=5)),
                ('offer_expiration_in_days', models.IntegerField(default=5)),
                ('discount_percentage', models.FloatField(blank=True, null=True)),
                ('message', models.CharField(blank=True, max_length=500, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('deleted_at', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('can_delete', models.BooleanField(default=True)),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField()),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
                ('history_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('page', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to='api.Page')),
                ('user', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'historical promotion campaign',
                'db_table': 'promotion_campaign_history',
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': 'history_date',
            },
            bases=(simple_history.models.HistoricalChanges, models.Model),
        ),
        migrations.AddIndex(
            model_name='promotioncampaign',
            index=models.Index(fields=['id'], name='promotion_c_id_1b830f_idx'),
        ),
    ]
