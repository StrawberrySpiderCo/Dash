from django.shortcuts import render
from django.shortcuts import render, get_object_or_404, redirect
from .models import WikiEntry
from .forms import WikiEntryForm

def wiki_list(request):
    entries = WikiEntry.objects.all()
    return render(request, 'wiki/wiki_list.html', {'entries': entries})

def wiki_detail(request, pk):
    entry = get_object_or_404(WikiEntry, pk=pk)
    return render(request, 'wiki/wiki_detail.html', {'entry': entry})

def wiki_new(request):
    if request.method == "POST":
        form = WikiEntryForm(request.POST)
        if form.is_valid():
            entry = form.save(commit=False)
            entry.save()
            return redirect('wiki:wiki_detail', pk=entry.pk)
    else:
        form = WikiEntryForm()
    return render(request, 'wiki/wiki_edit.html', {'form': form})

def wiki_edit(request, pk):
    entry = get_object_or_404(WikiEntry, pk=pk)
    if request.method == "POST":
        form = WikiEntryForm(request.POST, instance=entry)
        if form.is_valid():
            entry = form.save(commit=False)
            entry.save()
            return redirect('wiki:wiki_detail', pk=entry.pk)
    else:
        form = WikiEntryForm(instance=entry)
    return render(request, 'wiki/wiki_edit.html', {'form': form})

def wikis_view(request):
    return render(request, 'wikis.html')

