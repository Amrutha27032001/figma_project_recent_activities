from django.db import models

class RecentActivity(models.Model):
    # Define the fields for RecentActivity here
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    # Add other fields as required

    def __str__(self):
        return self.action
# Create your models here.
