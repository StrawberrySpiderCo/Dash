from django.db import models

class WikiEntry(models.Model):
    title = models.CharField(max_length=100, default='')
    content = models.TextField(default='')
    author = models.TextField(default='')
    #views = models.IntegerField(default='')
    #comments = models.TextField(default='')
    tags = models.TextField(default='')

    def __str__(self):
        return self.title
