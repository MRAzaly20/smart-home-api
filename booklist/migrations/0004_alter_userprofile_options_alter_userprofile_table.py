# Generated by Django 5.0.3 on 2024-03-22 01:02

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('booklist', '0003_userprofile'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='userprofile',
            options={'ordering': ['phone_number'], 'verbose_name': 'UserProfile', 'verbose_name_plural': 'UserProfile'},
        ),
        migrations.AlterModelTable(
            name='userprofile',
            table='user_profile',
        ),
    ]
