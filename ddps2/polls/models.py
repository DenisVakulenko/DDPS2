from django.db import models


class User(models.Model):
	name 	 = models.CharField(max_length=200)
	password = models.CharField(max_length=200)
	age      = models.IntegerField(default=21)

	def __str__(self):
		return self.name + " (" + self.age + ")"


class Song(models.Model):
	author = models.CharField(max_length=200)
	name   = models.CharField(max_length=200)

	def __str__(self):
		return self.author + " - " + self.name

	def dict(self):
		return {'author': str(self.author), 'name': str(self.name)}


class SongUser(models.Model):
	songID = models.ForeignKey(Song)
	userID = models.ForeignKey(User)

