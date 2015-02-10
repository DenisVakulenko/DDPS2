from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.template import RequestContext, loader
from django.views.decorators.csrf import csrf_exempt
from polls import forms
from polls import models

from polls.models import User, Song

import requests
import json
import urllib, urllib2


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
code = 'codecodecode'


def test(request):
	reqtext = "/polls/oauth2/getgrant?client_id=" + client_id + "&redirect_uri=http://127.0.0.1:8000/polls/app/privatedata"
	return redirect(reqtext)

def app_privatedata(request):
    if request.method == "POST":
        return request.data
    else:
        code = request.GET['code']
        if code is None:
            return "bad request"


        # k = requests.post('http://127.0.0.1:8000/polls/oauth2/gettoken?client_id=' + client_id + '&client_secret=' + client_secret + '&code=' + code)

        post_data = [('client_id',client_id),('client_secret',client_secret),('code',code),]     # a sequence of two element tuples
        k = urllib2.urlopen('http://127.0.0.1:8000/polls/oauth2/gettoken/', urllib.urlencode(post_data))
        js = k.read()
        
        # if k.status_code/100 != 2:
        #     return "Internal request error"
        # raise Exception(str(js))
        access_token = json.loads(js) # k.json()["access_token"]

        access_token = access_token["access_token"]

        url = 'http://127.0.0.1:8000/polls/oauth2/getprivate/?page=1&oauth_token=' + access_token
        response = requests.get(url)
        if response.status_code/100 != 2:
            return "Internal request error"

        return HttpResponse(response)

def oauth_grant(request):
	if request.method == 'POST':		
		return redirect(request.GET['redirect_uri'] + "?code=" + code)
	else:
		if not "user_id" in request.session:
			return redirect("/polls/login?&oauth=1&client_id={0}&redirect_uri={1}".format(request.GET['client_id'], request.GET['redirect_uri']), 302)

		return render(request, "oauth.html")

@csrf_exempt
def test2(request):
	if request.method == 'POST':
		response_data = {}
		response_data['access_token'] = 'tokentoken'
		return HttpResponse(json.dumps(response_data), content_type="application/json")
	response_data = {}
	response_data['access_token'] = 'get'
	return HttpResponse(json.dumps(response_data), content_type="application/json")

@csrf_exempt
def oauth_token(request):
	if request.method == 'POST':
		cid = request.POST['client_id']
		cs = request.POST['client_secret']

		if cid == client_id and cs == client_secret and request.POST['code'] == code:
			response_data = {}
			response_data['access_token'] = 'tokentoken'
			return HttpResponse(json.dumps(response_data), content_type="application/json")
	response_data = {}
	response_data['error'] = 'invalid parameters'
	return HttpResponse(json.dumps(response_data), content_type="application/json")


from django.core.paginator import Paginator

@csrf_exempt
def oauth_private(request):
	try:
		if request.GET['oauth_token'] == 'tokentoken':
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