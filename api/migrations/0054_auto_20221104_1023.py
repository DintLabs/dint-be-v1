# Generated by Django 2.2 on 2022-11-04 10:23

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0053_auto_20221102_0542'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='historicalposts',
            name='total_comments',
        ),
        migrations.RemoveField(
            model_name='historicalposts',
            name='total_likes',
        ),
        migrations.RemoveField(
            model_name='posts',
            name='total_comments',
        ),
        migrations.RemoveField(
            model_name='posts',
            name='total_likes',
        ),
        migrations.AlterField(
            model_name='postcomments',
            name='post',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='post_comment', to='api.Posts'),
        ),
        migrations.AlterField(
            model_name='postcomments',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_comment', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='postlikes',
            name='post',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='like_post', to='api.Posts'),
        ),
        migrations.AlterField(
            model_name='postlikes',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='like_user', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='posts',
            name='page',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='post_page', to='api.Page'),
        ),
        migrations.AlterField(
            model_name='posts',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_posts', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='userfeeds',
            name='post',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_posts', to='api.Posts'),
        ),
        migrations.AlterField(
            model_name='userfeeds',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_feeds', to=settings.AUTH_USER_MODEL),
        ),
    ]
