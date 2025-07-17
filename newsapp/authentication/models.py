from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from datetime import timedelta
from django.utils import timezone
import uuid
import secrets

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=20, unique=True)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # MFA fields
    is_mfa_enabled = models.BooleanField(default=True)  
    mfa_secret = models.CharField(max_length=100, blank=True, null=True)  
    primary_mfa_method = models.CharField(max_length=10, default='totp', choices=[
        ('totp', 'TOTP'),
        ('email', 'Email'),
    ])
    
    login_token = models.CharField(max_length=255, blank=True, null=True)
    login_token_created_at = models.DateTimeField(blank=True, null=True)
    
    mfa_setup_token = models.CharField(max_length=255, blank=True, null=True)
    mfa_setup_token_created_at = models.DateTimeField(blank=True, null=True)
    mfa_setup_method = models.CharField(max_length=10, blank=True, null=True)

    password_reset_token = models.CharField(max_length=255, blank=True, null=True)
    password_reset_token_created_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.user.username

    def is_otp_valid(self, otp_code):
        """Check if the provided OTP code is valid and not expired"""
        if not self.otp_code or not self.otp_created_at:
            return False
        
        if self.otp_code != otp_code:
            return False
        
        expiry_time = self.otp_created_at + timedelta(minutes=5)
        if timezone.now() > expiry_time:
            return False
        
        return True
    
    def clear_otp(self):
        """Clear OTP after successful verification"""
        self.otp_code = None
        self.otp_created_at = None
        self.save()
    
    def is_login_token_valid(self):
        """Check if login token is valid (5 minutes expiry)"""
        if not self.login_token or not self.login_token_created_at:
            return False
        
        expiration_time = self.login_token_created_at + timedelta(minutes=5)
        return timezone.now() < expiration_time
    
    def generate_login_token(self):
        """Generate a temporary login token for MFA"""
        self.login_token = secrets.token_urlsafe(32)
        self.login_token_created_at = timezone.now()
        self.save()
        return self.login_token
    
    def generate_setup_token(self, method):
        """Generate a temporary setup token for MFA"""
        self.mfa_setup_token = secrets.token_urlsafe(32)
        self.mfa_setup_token_created_at = timezone.now()
        self.mfa_setup_method = method
        self.save()
        return self.mfa_setup_token
    
    def is_setup_token_valid(self):
        """Check if setup token is valid (5 minutes expiry)"""
        if not self.mfa_setup_token or not self.mfa_setup_token_created_at:
            return False
        
        expiration_time = self.mfa_setup_token_created_at + timedelta(minutes=5)
        return timezone.now() < expiration_time
    

    def generate_password_reset_token(self):
        """Generate a password reset token (15 minutes expiry)"""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_token_created_at = timezone.now()
        self.save()
        return self.password_reset_token
    
    def is_password_reset_token_valid(self):
        """Check if password reset token is valid (15 minutes expiry)"""
        if not self.password_reset_token or not self.password_reset_token_created_at:
            return False
        
        expiration_time = self.password_reset_token_created_at + timedelta(minutes=15)
        return timezone.now() < expiration_time
    
    def clear_password_reset_token(self):
        """Clear password reset token after use"""
        self.password_reset_token = None
        self.password_reset_token_created_at = None
        self.save()
    
    def get_available_mfa_methods(self):
        """Get available MFA methods for the user"""
        return ["email", "totp"]
    
    def get_enabled_mfa_methods(self):
        """Get enabled MFA methods for the user"""
        enabled = []
        if self.is_mfa_enabled:
            if self.mfa_secret:
                enabled.append("totp")
            if self.user.email:
                enabled.append("email")
        return enabled


class MFABackupCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='backup_codes')
    code = models.CharField(max_length=8, unique=True)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        unique_together = ['user', 'code']
    
    def __str__(self):
        return f"{self.user.username} - {self.code}"
    
    @classmethod
    def generate_codes_for_user(cls, user, count=5):
        """Generate backup codes for a user"""
        cls.objects.filter(user=user).delete()
        
        codes = []
        for _ in range(count):
            code = str(secrets.randbelow(100000000)).zfill(8)
            backup_code = cls.objects.create(user=user, code=code)
            codes.append(code)
        
        return codes
    
    @classmethod
    def verify_code(cls, user, code):
        """Verify a backup code"""
        try:
            backup_code = cls.objects.get(user=user, code=code, is_used=False)
            backup_code.is_used = True
            backup_code.used_at = timezone.now()
            backup_code.save()
            return True
        except cls.DoesNotExist:
            return False
    
    @classmethod
    def get_remaining_codes_count(cls, user):
        """Get count of remaining backup codes"""
        return cls.objects.filter(user=user, is_used=False).count()
    
    @classmethod
    def get_last_used_date(cls, user):
        """Get the last used date of backup codes"""
        last_used = cls.objects.filter(user=user, is_used=True).order_by('-used_at').first()
        return last_used.used_at if last_used else None


class MFAAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_attempts')
    method = models.CharField(max_length=10, choices=[
        ('totp', 'TOTP'),
        ('email', 'Email'),
        ('backup', 'Backup Code'),
    ])
    success = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.method} - {'Success' if self.success else 'Failed'}"


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
    instance.profile.save()