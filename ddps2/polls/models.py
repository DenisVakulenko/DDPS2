from django.db import models


import hashlib

from datetime import datetime, timedelta


from django.db.models.signals import post_init

import json
import pprint

def dump(v):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(v)

def debug(msg):
    print "DEBUG: " + str(msg)


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





class Authcode(models.Model):
    app_id = models.CharField(max_length=64)
    user = models.ForeignKey(User)
    code = models.CharField(max_length=64)
    creationTime = models.DateTimeField()
    redirect_uri = models.URLField()

    def generateCode(self):
        self.code = hashlib.md5(self.user.name + self.app_id + str(datetime.now().microsecond)).hexdigest()

    def isValid(self):
        dif = datetime.now() - self.creationTime
        dump(self.creationTime)
        debug(str(dif))
        delta = timedelta(minutes=20)
        debug(str(delta))
        return dif <= delta


def authcodePostInit(**kwargs):
    instance = kwargs.get('instance')
    instance.creationTime = datetime.now()

post_init.connect(authcodePostInit, Authcode)

def exact(str):
    return r'\b' + str + r'\b'
def getAuthcode(code):
    # debug("getAuthcode: " + code)
    authcodes = Authcode.objects.filter(code__iregex=exact(code))
    if len(authcodes) > 0:
        code = authcodes[0]
        if code.isValid():
            debug("valid auth")
            return authcodes[0]
        debug("invalid auth")
        code.delete()
    return None


class Token(models.Model):
    user = models.ForeignKey(User)
    accessToken = models.CharField(max_length=64)
    refreshToken = models.CharField(max_length=64)
    expirationDate = models.DateTimeField()

    def generateAccessToken(self):
        debug("generate access token")
        source = self.user.name + str(datetime.now().microsecond)
        code = hashlib.md5(source).hexdigest()

        if len(Token.objects.filter(accessToken__iregex=exact(code))) > 0:
            self.generateAccessToken()
        self.accessToken = code

    def generateRefreshToken(self):
        debug("generate refresh token")
        source = str(self.accessToken) + str(datetime.now().microsecond)
        code = hashlib.md5(source).hexdigest()

        if len(Token.objects.filter(refreshToken__iregex=exact(code))) > 0:
            self.generateRefreshToken()
        self.refreshToken = code


    def isValid(self):
        debug("is valid date function")
        expDate = self.expirationDate
        now = datetime.now(tz=pytz.utc)
        now = now + timedelta(minutes=2)
        result = (now >= expDate)
        return result

    def init(self):
        debug("token init")
        self.generateAccessToken()
        self.generateRefreshToken()
        self.expirationDate = datetime.now() + timedelta(minutes=2)
        debug("token init finish")

    def json(self):
        result = { }
        result['access_token'] = self.accessToken
        result['refresh_token'] = self.refreshToken
        result['token_type'] = "Bearer"
        result['expires_in'] = str(2*60)
        return json.dumps(result)

def getToken(refreshToken):
    debug("getToken")
    try:
        return list(Token.objects.filter(refreshToken__iregex=exact(refreshToken)))[0]
    except IndexError:
        debug("none")
        return None

def findAccessToken(accessToken):
    debug("getToken")
    try:
        return list(Token.objects.filter(accessToken__iregex=exact(accessToken)))[0]
    except IndexError:
        debug("none")
        return None

# class Applications(models.Model):
# 	secret = models.ForeignKey(Song)
# 	appid = models.ForeignKey(User)


# class Tokens(models.Model):
# 	token = models.ForeignKey(Song)
# 	refrtoken = models.ForeignKey(User)
# 	exp = models.ForeignKey(Song)
