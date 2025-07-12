# core/urls.py
from django.urls import path
from .views import RegisterView, NewsAPIView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('news/', NewsAPIView.as_view(), name='news_api'),
]