# Generated by Django 5.0.2 on 2024-02-25 02:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('azureauth', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='SSOUser',
        ),
        migrations.AddField(
            model_name='user',
            name='sso',
            field=models.BooleanField(default=False),
        ),
    ]