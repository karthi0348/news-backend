from django.urls import path
from .views import RegisterView, LoginView, OTPVerificationView, ResendOTPView, NewsAPIView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify_otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend_otp'),
    path('news/', NewsAPIView.as_view(), name='news_api'),
]
