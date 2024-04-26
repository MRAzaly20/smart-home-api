from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(
            user=instance,
            phone_number=kwargs.get('phone_number', ''),
            address=kwargs.get('address', '')
        )
    else:
        # Update existing profile
        profile = UserProfile.objects.get(user=instance)
        profile.phone_number = kwargs.get('phone_number', profile.phone_number)
        profile.address = kwargs.get('address', profile.address)
        profile.save()
