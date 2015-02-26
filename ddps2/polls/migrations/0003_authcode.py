# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('polls', '0002_token'),
    ]

    operations = [
        migrations.CreateModel(
            name='Authcode',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('app_id', models.CharField(max_length=64)),
                ('code', models.CharField(max_length=64)),
                ('creationTime', models.DateTimeField()),
                ('redirect_uri', models.URLField()),
                ('user', models.ForeignKey(to='polls.User')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
