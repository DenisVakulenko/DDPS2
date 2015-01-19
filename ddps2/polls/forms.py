from django import forms

class RegistrationForm(forms.Form):
	name     = forms.CharField(label='Name', max_length=200)
	password = forms.CharField(label='Pass', max_length=200)
	age      = forms.CharField(label='Age')

class LoginForm(forms.Form):
	name     = forms.CharField(label='Name', max_length=200)
	password = forms.CharField(label='Pass', max_length=200)