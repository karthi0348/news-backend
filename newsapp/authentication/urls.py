from django.urls import path
from .views import (
    RegisterView, LoginView, MFAMethodsView, EmailMFAEnableView,
    EmailMFAVerifySetupView, TOTPSetupView, TOTPVerifySetupView,
    MFAVerifyView, MFADisableView, BackupCodesRegenerateView,
    BackupCodesView,PasswordResetRequestView, PasswordResetVerifyView,NewsAPIView,MFASendOTPView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    
    # MFA Methods Management
    path('mfa/methods/', MFAMethodsView.as_view(), name='mfa_methods'),
    
    # Email MFA
    path('mfa/email/enable/', EmailMFAEnableView.as_view(), name='email_mfa_enable'),
    path('mfa/email/verify-setup/', EmailMFAVerifySetupView.as_view(), name='email_mfa_verify_setup'),
    
    # TOTP MFA
    path('mfa/totp/setup/', TOTPSetupView.as_view(), name='totp_setup'),
    path('mfa/totp/verify-setup/', TOTPVerifySetupView.as_view(), name='totp_verify_setup'),
    
    # MFA Verification (Login & Operations)
    path('auth/mfa/verify/', MFAVerifyView.as_view(), name='mfa_verify'),
     path('auth/mfa/send-otp/', MFASendOTPView.as_view(), name='mfa_send_otp'),
    
    # MFA Management
    path('mfa/disable/', MFADisableView.as_view(), name='mfa_disable'),
    path('mfa/backup-codes/regenerate/', BackupCodesRegenerateView.as_view(), name='backup_codes_regenerate'),
    path('mfa/backup-codes/', BackupCodesView.as_view(), name='backup_codes'),

    path('password-reset-request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset-verify/', PasswordResetVerifyView.as_view(), name='password_reset_verify'),
    path('news/', NewsAPIView.as_view(), name='news_api'),


]