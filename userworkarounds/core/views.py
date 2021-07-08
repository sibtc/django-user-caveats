from django.shortcuts import render, redirect

from core.forms import UserCreationForm


def signup(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("success")
    else:
        form = UserCreationForm()
    return render(request, "core/signup.html", {"form": form})


def success(request):
    return render(request, "core/success.html")
