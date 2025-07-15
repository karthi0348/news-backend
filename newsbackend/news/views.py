from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate 
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
from django.utils import timezone
import random
import requests

from rest_framework_simplejwt.tokens import AccessToken, RefreshToken



from .serializers import UserSerializer, LoginSerializer, OTPSerializer, EmailOnlySerializer
from .models import UserProfile 

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

class LoginView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

        authenticated_user = authenticate(request, username=user.username, password=password)

        if authenticated_user is not None:
            user_profile = authenticated_user.profile

            otp_code = str(random.randint(100000, 999999))
            
            user_profile.otp_code = otp_code
            user_profile.otp_created_at = timezone.now()
            user_profile.save()

            try:
                send_mail(
                    'Your One-Time Password (OTP)',
                    f'Your OTP for login is: {otp_code}\nThis OTP is valid for 5 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [authenticated_user.email],
                    fail_silently=False,
                )
                return Response({"otp_required": True, "message": "OTP sent to your email. Please verify."}, status=status.HTTP_200_OK)
            
            except Exception as e:
                return Response({"detail": f"Failed to send OTP email: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

class OTPVerificationView(APIView):
    """
    API endpoint for OTP verification.
    If OTP is valid, generates and returns JWT access and refresh tokens.
    """
    permission_classes = (AllowAny,)
    serializer_class = OTPSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        entered_otp = serializer.validated_data['otp_code']

        try:
            user = User.objects.get(email=email)
            user_profile = user.profile
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user_profile.is_otp_valid(entered_otp):

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            user_profile.otp_code = None 
            user_profile.otp_created_at = None
            user_profile.save()

            return Response({
                "detail": "Login successful.",
                "access": access_token,
                "refresh": str(refresh)
            }, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = EmailOnlySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
            user_profile = user.profile
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user_profile.otp_created_at and (timezone.now() - user_profile.otp_created_at) < timedelta(seconds=60):
            time_remaining = (user_profile.otp_created_at + timedelta(seconds=60)) - timezone.now()
            seconds = int(time_remaining.total_seconds())
            return Response(
                {"detail": f"Please wait {seconds} seconds before resending OTP."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        otp_code = str(random.randint(100000, 999999))

        user_profile.otp_code = otp_code
        user_profile.otp_created_at = timezone.now()
        user_profile.save()

        try:
            send_mail(
                'Your New One-Time Password (OTP)',
                f'Your new OTP for login is: {otp_code}\nThis OTP is valid for 5 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({"detail": "New OTP sent to your email."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": f"Failed to send new OTP email: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class NewsAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        query = request.query_params.get('q', '').strip()

        if not query:
            return Response(
                {"detail": "The 'q' (query) parameter is required for news searches."},
                status=status.HTTP_400_BAD_REQUEST
            )

        page_size = request.query_params.get('pageSize', 10)
        sort_by = request.query_params.get('sortBy', 'publishedAt')
        from_date = request.query_params.get('from', '')

        api_key = settings.NEWS_API_KEY

        if not api_key:
            return Response({"detail": "News API Key not configured in settings."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        url = "https://newsapi.org/v2/everything"
        params = {
            'q': query,
            'sortBy': sort_by,
            'pageSize': page_size,
            'apiKey': api_key,
        }

        if from_date:
            params['from'] = from_date

        params['language'] = 'en'

        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            return Response(data)
        except requests.exceptions.RequestException as e:
            error_detail = "Error fetching news from external API."
            if response.status_code == 400:
                news_api_error = response.json().get('message', 'Bad Request')
                error_detail = f"News API Error (400): {news_api_error}"
            elif response.status_code == 401:
                error_detail = "News API Error (401): Unauthorized. Check your API key."
            elif response.status_code == 426:
                error_detail = "News API Error (426): Upgrade required. You might be using a feature not available on your plan (e.g., older dates, too many results)."
            elif response.status_code == 429:
                error_detail = "News API Error (429): Too Many Requests. You've hit your usage limits."
            elif response.status_code == 500:
                error_detail = "News API Error (500): Server-side issue from NewsAPI.org."

            return Response({"detail": error_detail}, status=response.status_code if response.status_code >= 400 else status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail": f"An unexpected server error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)