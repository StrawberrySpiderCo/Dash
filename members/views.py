from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
def create_user(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user = authenticate(username=username, password=password)
            login(request,user)
            messages.success(request,("Registration Successful"))
            return redirect ('/')
    else:
        form = UserCreationForm()

    return render(request, 'creation.html',{
        'form':form,
    })

def logout_user(request):
    logout(request)
    messages.success(request, ("Successfully logged out!"))
    return redirect('home')

# Create your views here.

def login_user(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('/')
            # Redirect to a success page.
        else:
            messages.success(request, "There was an error logging in. Please contact the website administrator.")

            # Return an 'invalid login' error message.

    # Handle the case when the request method is not POST
    return render(request, 'login.html')

def invalid_user(request):
    return render(request, "invalid.html")
