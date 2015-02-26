from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, HttpResponse, HttpResponseBadRequest
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt
from polls import forms
from polls import models	

from polls.models import User, Song, Authcode, Token

import requests
import json
import urllib, urllib2



def debug(msg):
    print "DEBUG: " + str(msg)



def index(request):
	if "user_id" in request.session:
		u = User.objects.get(id__exact=request.session['user_id'])
		s = 'logged in: ' + u.name + '; <a href="/polls/logout/">log out</a>; <a href="/polls/login/">log in with another username</a>'
	else:
		s = '<a href="/polls/login/">log in</a>'
	return HttpResponse(s + '<br><a href="/polls/registration/">register new user</a><br><br><a href="/polls/test/">test oauth2</a><br><a href="/polls/oauth2/getpublic">get public data</a><br><br><a href="/polls/allusers/">all users</a><br><a href="/polls/allsongs/">all songs</a>')

def registration(request):
	if request.method == 'POST':
		form = forms.RegistrationForm(request.POST)
		if form.is_valid():
			if User.objects.filter(name = request.POST['name']).count() == 0:
				# us = User.objects.all()
				# us.delete()
				u = models.User(name=request.POST['name'], password=request.POST['password'])
				u.save()
				return HttpResponse("<a href='/polls/'>home</a><br>registered new user: " + form.cleaned_data['name'] + "; users count: " + str(User.objects.all().count()))
			else:
				return HttpResponse("<a href='/polls/'>home</a><br>user already exists")
	else:
		form = forms.RegistrationForm()
	return render(request, 'registration.html', {'form':form})


def login(request):
	if request.method == 'POST':
		try:
			u = User.objects.get(name__exact=request.POST['name'])
			if u.password == request.POST['password']:
				request.session['user_id'] = u.id
				if 'oauth' in request.GET:
					return redirect("/polls/oauth2/getgrant?&client_id={0}&redirect_uri={1}".format(request.GET['client_id'], request.GET['redirect_uri']))
				else:
					return HttpResponse("<a href='/polls/'>home</a><br>you've logged in. id=" + str(u.id))
		except User.DoesNotExist:
			form = forms.LoginForm()
			return render(request, 'registration.html', {'form':form, 'msg':"wrong user or pass"})
	form = forms.LoginForm()
	return render(request, 'registration.html', {'form':form})

def logout(request):
	try:
		del request.session['user_id']
	except KeyError:
		pass
	return HttpResponse("<a href='/polls/'>home</a><br>you've logged out")


client_id = '123123'
client_secret = 'secretsecret'
token = 'tokentoken'
refresh_token = 'rfr_token'
code = 'codecodecode'


def test(request):
	reqtext = "/polls/oauth2/getgrant?response_type=code&response_type=code&client_id=" + client_id + "&redirect_uri=http://127.0.0.1:8000/polls/app/privatedata"
	return redirect(reqtext)

def app_privatedata(request):
    if request.method == "POST":
        return request.data
    else:
        code = request.GET['code']
        if code is None:
            return "bad request"
        # k = requests.post('http://127.0.0.1:8000/polls/oauth2/gettoken?client_id=' + client_id + '&client_secret=' + client_secret + '&code=' + code)

        post_data = [('grant_type','authorization_code'),('client_id',client_id),('client_secret',client_secret),('code',code),]
        k = urllib2.urlopen('http://127.0.0.1:8000/polls/oauth2/gettoken/', urllib.urlencode(post_data))
        js = k.read()
        
        # if k.status_code/100 != 2:
        #     return "Internal request error"
        # raise Exception(str(js))
        access_token = json.loads(js)
        access_token = access_token["access_token"]

        url = 'http://127.0.0.1:8000/polls/oauth2/getprivate/?page=2&oauth_token=' + access_token

        response = requests.get(url, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + access_token})
        if response.status_code/100 != 2:
            return "Internal request error"

        return HttpResponse(response)

def oauth_grant(request):
	if request.method == 'POST':
		global client_id
		u = User.objects.get(id__exact=request.session['user_id'])
		c = Authcode(user=u)
		c.redirect_uri = request.GET['redirect_uri']
		c.app_id = client_id
		c.generateCode()
		c.save()
		return redirect(request.GET['redirect_uri'] + "?code=" + c.code)
	else:
		g = request.GET
		resp_type = g.get('response_type')
		client_id = g.get('client_id')
		redirect_uri = g.get('redirect_uri')

		if redirect_uri is None:
			return HttpResponseBadRequest('Redirect uri is missing')
		if resp_type is None or client_id is None:
			return HttpResponseRedirect(errorInvalidRequest(redirect_uri))
		if resp_type != 'code':
			return HttpResponseRedirect(errorResponceType(redirect_uri))
		if client_id != client_id:
			return HttpResponseRedirect(errorAccessDenied(redirect_uri))

		if not "user_id" in request.session:
			return redirect("/polls/login?&oauth=1&client_id={0}&redirect_uri={1}".format(request.GET['client_id'], request.GET['redirect_uri']), 302)

		return render(request, "oauth.html")

@csrf_exempt
def oauth_token(request):
	if request.method == 'POST':
		#global token
		#global refresh_token

		cid = request.POST['client_id']
		cs = request.POST['client_secret']
		type = request.POST['grant_type']

		if type == 'authorization_code':
			code = models.getAuthcode(request.POST['code'])
			if code is None:
				return errorInvalidGrantJSON(None)
			# if code.redirect_uri != redirect_uri:
			# 	return errorInvalidGrantJSON(None)

			token = models.Token(user=code.user)

			if cid == client_id and cs == client_secret:

				token = Token(user=code.user)
				token.init()
				token.save()
				debug("access_token = " + token.accessToken)

				response_data = {}
				response_data['access_token'] = token.accessToken
				response_data['refresh_token'] = token.refreshToken
				response_data['token_type'] = "Bearer"
				response_data['expires_in'] = str(2*60)

				# code.delete()

				return HttpResponse(json.dumps(response_data), content_type="application/json")
			response_data = {}
			response_data['error'] = 'bad parameters'
			return HttpResponse(json.dumps(response_data), content_type="application/json")

		if type == 'refresh_token':
			refresh_token = request.POST['refresh_token']
			if refresh_token is None:
				return errorInvalidRequestJSON()

			token = models.getToken(refresh_token)
			if token is not None:
				token.init()
				token.save()
				return HttpResponse(token.json(), content_type="application/json")

			response_data = {}
			response_data['error'] = 'bad parameters'
			return HttpResponse(json.dumps(response_data), content_type="application/json")

		return errorUnsupportedGrantJSON()

	response_data = {}
	response_data['error'] = 'need post'
	return HttpResponse(json.dumps(response_data), content_type="application/json")



def errorInvalidRequest(redirect_uri):
    res = redirect_uri + "?error=" + "invalid_request"
    debug(res)
    return res
def errorResponceType(redirect_uri):
    res = redirect_uri + "?error=" + "unsupported_responce_type"
    debug(res)
    return res
def errorAccessDenied(redirect_uri):
    res = redirect_uri + "?error=" + "access_denied"
    debug(res)
    return res
def errorUnathourized(redirect_uri):
    res = redirect_uri + "?error=" + "unauthorized_client"
    debug(res)
    return res

def errorInvalidRequestJSON(redirect_uri=None):
    j = json.dumps({"error": "invalid_request"})
    debug("invalid_request")
    return HttpResponseBadRequest(j, content_type="application/json")
    if redirect_uri is None:
        return HttpResponseBadRequest(j, content_type="application/json")
    else:
        return HttpResponseRedirect(redirect_uri, j, content_type="application/json")
def errorUnsupportedGrantJSON(redirect_uri=None):
    j = json.dumps({"error": "unsupported_grant_type"})
    debug("unsupp_grant_type")
    return HttpResponseBadRequest(j, content_type="application/json")
    if redirect_uri is None:
        return HttpResponseBadRequest(j, content_type="application/json")
    else:
        return HttpResponseRedirect(redirect_uri, j, content_type="application/json")
def errorInvalidGrantJSON(redirect_uri=None):
    j = json.dumps({"error": "invalid_grant"})
    debug("invalid_grant")
    return HttpResponseBadRequest(j, content_type="application/json")
    if redirect_uri is None:
        return HttpResponseBadRequest(j, content_type="application/json")
    else:
        return HttpResponseRedirect(redirect_uri, j, content_type="application/json")
def errorInvalidClientJSON(redirect_uri=None):
    j = json.dumps({"error": "invalid_client"})
    debug("invalid_client")
    return HttpResponseBadRequest(j, content_type="application/json")
    if redirect_uri is None:
        return HttpResponseBadRequest(j, content_type="application/json")
    else:
        return HttpResponseRedirect(redirect_uri, j, content_type="application/json")





# def getBearerToken(request):
#     debug("token request")
#     bearer = None

#     if "HTTP_AUTHORIZATION" in request.META.keys():
#         b_list = request.META["HTTP_AUTHORIZATION"].split(' ')

#         if len(b_list) > 1 and b_list[0].lower() == 'bearer':
#             bearer = b_list[1]
#             debug("Bearer: " + bearer)

#     if bearer is not None:
#         return models.getAccessToken(bearer)

#     return None




def handleRefreshTokenRequest(request):
    debug("handle refresh request")
    post = request.POST
    refresh_token = post.get('refresh_token')

    token = models.getToken(refresh_token)
    if token is not None:
        token.init()
        token.save()
        return HttpResponse(token.json(), content_type="application/json")

    return HttpResponseBadRequest("err")


def handleAccessTokenRequest(request):
    debug("handle access token request")
    post = request.POST
    code = post.get('code')
    redirect_uri = post.get('redirect_uri')

    if redirect_uri is None:
        debug("redirect uri is missing")
        return HttpResponseBadRequest('Redirect uri is missing')

    if code is None:
        return errorInvalidRequestJSON(redirect_uri)

    code = models.getAuthcode(code)
    if code is None:
        return errorInvalidGrantJSON(redirect_uri)

    if code.redirect_uri != redirect_uri:
        return errorInvalidGrantJSON(None)

    token = models.Token(user=code.user)
    token.init()
    token.save()

    code.delete()

    debug("access_token = " + token.accessToken)

    return HttpResponse(content=token.json(), content_type="application/json")



@csrf_exempt
def test2(request):
	if request.method == 'POST':
		post = request.POST

		# if not httpBasicAuth(request):
		#     return errorInvalidClientJSON()

		type = post.get('grant_type')

		if type == 'refresh_token':
			return handleRefreshTokenRequest(request)

		if type == 'authorization_code':
			return handleAccessTokenRequest(request)

		# if type == 'refresh_token':
		# 	response_data = {}
		# 	response_data['access_token'] = 'tokentoken'
		# 	response_data['refresh_token'] = 'refrtoken'
		# 	return HttpResponse(json.dumps(response_data), content_type="application/json")

		# if type == 'authorization_code':
		# 	response_data = {}
		# 	response_data['access_token'] = 'tokentoken'
		# 	response_data['refresh_token'] = 'refrtoken'
		# 	return HttpResponse(json.dumps(response_data), content_type="application/json")
			#return handleAccessTokenRequest(request)

	response_data = {}
	response_data['access_token'] = 'get'
	return HttpResponse(json.dumps(response_data), content_type="application/json")

from django.core.paginator import Paginator



def chkToken(request):
    debug("token request")
    bearer = None

    if "HTTP_AUTHORIZATION" in request.META.keys():
        b_list = request.META["HTTP_AUTHORIZATION"].split(' ')

        if len(b_list) > 1 and b_list[0].lower() == 'bearer':
            bearer = b_list[1]
            debug("Bearer: " + bearer)
    
    if bearer is not None:
        return models.findAccessToken(bearer)

    if 'oauth_token' in requests.GET:
        return models.findAccessToken(request.GET['oauth_token'])

    return false


@csrf_exempt
def oauth_private(request):
	try:
		if chkToken(request):
			records = Song.objects.all()
			p = Paginator([rec.dict() for rec in records], 2)

			if 'page' in request.GET:
				page = request.GET.get('page')
			else:
				page = 1

			try:
				records_json = p.page(page).object_list
			except PageNotAnInteger:
				records_json = p.page(1).object_list
			except EmptyPage:
				records_json = p.page(p.num_pages).object_list

			c = json.dumps(records_json)
			return HttpResponse('{ "page" : ' + str(page) + ', "pages" : ' + str(p.num_pages) + ', "content" : ' + c + '}', content_type="application/json")
		else:
			return HttpResponse(json.dumps({'error': 'bad token'}), content_type="application/json")
	except Exception as e:
		return HttpResponse(json.dumps({'error': str(e)}), content_type="application/json")


@csrf_exempt
def oauth_me(request):
    try:
        if chkToken(request):
            u = User.objects.get(id__exact=request.session['user_id'])
            response_data = {}
            response_data['name'] = u.name
            response_data['age'] = u.age

            return HttpResponse(json.dumps(response_data), content_type="application/json")
        return HttpResponse(json.dumps({'error': 'bad token'}), content_type="application/json")
    except Exception as e:
        return json.dumps({'error': str(e)})


@csrf_exempt
def oauth_public(request):
    try:
        records = Song.objects.all()
        records_json = [rec.dict() for rec in records]
        return HttpResponse(json.dumps(records_json), content_type="application/json")
    except Exception as e:
        return json.dumps({'error': str(e)})


def allusers(request):
	ulist = User.objects.all()
	template = loader.get_template('list.html')
	context = RequestContext(request, {
		'list': ulist,
	})
	return HttpResponse(template.render(context))

def allsongs(request):
	# Song(name='Show me how to live', author='Audioslave').save()
	# Song(name='We Will Rock You', author='Queen').save()
	# Song(name='Rock And Roll Music', author='The Beatles').save()
	# Song(name='Bohemian Rhapsody', author='Queen').save()

	latest_question_list = Song.objects.all()
	template = loader.get_template('list.html')
	context = RequestContext(request, {
		'list': latest_question_list,
	})
	return HttpResponse(template.render(context))