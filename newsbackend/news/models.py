from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from datetime import timedelta
from django.utils import timezone 

class UserProfile(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.user.username

    def is_otp_valid(self, entered_otp):

        if not self.otp_code or not self.otp_created_at:
            return False

        expiration_time = self.otp_created_at + timedelta(minutes=5)
        
        return self.otp_code == entered_otp and timezone.now() < expiration_time

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

    instance.profile.save()