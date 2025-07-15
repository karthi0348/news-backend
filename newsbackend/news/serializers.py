from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User registration.
    """
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login (email and password).
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class OTPSerializer(serializers.Serializer):
    """
    Serializer for OTP verification.
    """
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)

class EmailOnlySerializer(serializers.Serializer):
    """
    Serializer for requests that only require an email address (e.g., resend OTP).
    """
    email = serializers.EmailField()

