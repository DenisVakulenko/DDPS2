# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('polls', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('accessToken', models.CharField(max_length=64)),
                ('refreshToken', models.CharField(max_length=64)),
                ('expirationDate', models.DateTimeField()),
                ('user', models.ForeignKey(to='polls.User')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
