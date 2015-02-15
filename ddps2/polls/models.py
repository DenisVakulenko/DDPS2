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


class Token(models.Model):
    user = models.ForeignKey(User)
    accessToken = models.CharField(max_length=64)
    refreshToken = models.CharField(max_length=64)
    expirationDate = models.DateTimeField()

    def generateAccessToken(self):
        debug("generate access token")
        source = self.user.email + str(datetime.now().microsecond)
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




# class Applications(models.Model):
# 	secret = models.ForeignKey(Song)
# 	appid = models.ForeignKey(User)


# class Tokens(models.Model):
# 	token = models.ForeignKey(Song)
# 	refrtoken = models.ForeignKey(User)
# 	exp = models.ForeignKey(Song)
