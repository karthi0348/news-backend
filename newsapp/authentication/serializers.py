from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, MFABackupCode
import pyotp
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for User registration.
    """
    userName = serializers.CharField(source='username', max_length=150)
    firstName = serializers.CharField(source='first_name', max_length=30)
    lastName = serializers.CharField(source='last_name', max_length=30)
    phoneNumber = serializers.CharField(max_length=20)
    password = serializers.CharField(write_only=True, min_length=8)
    
    class Meta:
        model = User
        fields = ('userName', 'email', 'password', 'firstName', 'lastName', 'phoneNumber')
    
    def validate_userName(self, value):
        """Check if username is unique"""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value
    
    def validate_email(self, value):
        """Check if email is unique"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value
    
    def validate_phoneNumber(self, value):
        """Check if phone number is unique"""
        if UserProfile.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("Phone number already exists")
        return value

    def create(self, validated_data):
        phone_number = validated_data.pop('phoneNumber')
        
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        
        # Update the user profile with phone number
        user.profile.phone_number = phone_number
        user.profile.save()
        
        return user


class UserResponseSerializer(serializers.ModelSerializer):
    """
    Serializer for User registration response.
    """
    userId = serializers.CharField(source='profile.uuid', read_only=True)
    firstName = serializers.CharField(source='first_name', read_only=True)
    lastName = serializers.CharField(source='last_name', read_only=True)
    isEmailVerified = serializers.BooleanField(source='profile.is_email_verified', read_only=True)
    createdAt = serializers.DateTimeField(source='profile.created_at', read_only=True)
    
    class Meta:
        model = User
        fields = ('userId', 'email', 'firstName', 'lastName', 'isEmailVerified', 'createdAt')


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    username = serializers.CharField()
    password = serializers.CharField()


class LoginResponseUserSerializer(serializers.ModelSerializer):
    """
    Serializer for user data in login response.
    """
    userId = serializers.CharField(source='profile.uuid', read_only=True)
    firstName = serializers.CharField(source='first_name', read_only=True)
    lastName = serializers.CharField(source='last_name', read_only=True)
    userName = serializers.CharField(source='username', read_only=True)
    isMfaEnabled = serializers.BooleanField(source='profile.is_mfa_enabled', read_only=True)
    
    class Meta:
        model = User
        fields = ('userId', 'email', 'firstName', 'lastName', 'userName', 'isMfaEnabled')


# MFA Serializers
class MFAMethodsSerializer(serializers.Serializer):
    """
    Serializer for MFA methods response.
    """
    available = serializers.ListField(child=serializers.CharField())
    enabled = serializers.ListField(child=serializers.CharField())
    primary = serializers.CharField()
    hasBackupCodes = serializers.BooleanField()


class EmailMFAEnableSerializer(serializers.Serializer):
    """
    Serializer for enabling Email MFA.
    """
    emailAddress = serializers.EmailField()
    
    def validate_emailAddress(self, value):
        """Validate email address matches user's email"""
        user = self.context['request'].user
        if value != user.email:
            raise serializers.ValidationError("Email address must match your account email")
        return value


class MFASetupResponseSerializer(serializers.Serializer):
    """
    Serializer for MFA setup response.
    """
    setupToken = serializers.CharField()
    expiresIn = serializers.IntegerField()
    method = serializers.CharField()


class MFAVerifySetupSerializer(serializers.Serializer):
    """
    Serializer for verifying MFA setup.
    """
    setupToken = serializers.CharField()
    verificationCode = serializers.CharField(max_length=6)
    
    def validate_setupToken(self, value):
        """Validate setup token"""
        try:
            user_profile = UserProfile.objects.get(mfa_setup_token=value)
            if not user_profile.is_setup_token_valid():
                raise serializers.ValidationError("Setup token has expired")
            return value
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError("Invalid setup token")


class MFAVerifySetupResponseSerializer(serializers.Serializer):
    """
    Serializer for MFA setup verification response.
    """
    method = serializers.CharField()
    backupCodes = serializers.ListField(child=serializers.CharField())


class MFAVerifySerializer(serializers.Serializer):
    """
    Serializer for MFA verification during login.
    """
    loginToken = serializers.CharField()
    verificationCode = serializers.CharField(max_length=6, required=False)
    backupCode = serializers.CharField(max_length=8, required=False)
    method = serializers.CharField(required=False)
    
    def validate(self, attrs):
        """Validate that either verification code or backup code is provided"""
        if not attrs.get('verificationCode') and not attrs.get('backupCode'):
            raise serializers.ValidationError("Either verificationCode or backupCode must be provided")
        
        if attrs.get('verificationCode') and attrs.get('backupCode'):
            raise serializers.ValidationError("Cannot provide both verificationCode and backupCode")
        
        return attrs
    
    def validate_loginToken(self, value):
        """Validate login token"""
        try:
            user_profile = UserProfile.objects.get(login_token=value)
            if not user_profile.is_login_token_valid():
                raise serializers.ValidationError("Login token has expired")
            return value
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError("Invalid login token")


class MFAVerifyResponseSerializer(serializers.Serializer):
    """
    Serializer for MFA verification response.
    """
    user = LoginResponseUserSerializer()
    tokens = serializers.DictField()


class MFADisableSerializer(serializers.Serializer):
    """
    Serializer for disabling MFA.
    """
    verificationCode = serializers.CharField(max_length=6, required=False)
    backupCode = serializers.CharField(max_length=8, required=False)
    method = serializers.CharField(required=False)
    
    def validate(self, attrs):
        """Validate that either verification code or backup code is provided"""
        if not attrs.get('verificationCode') and not attrs.get('backupCode'):
            raise serializers.ValidationError("Either verificationCode or backupCode must be provided")
        
        if attrs.get('verificationCode') and attrs.get('backupCode'):
            raise serializers.ValidationError("Cannot provide both verificationCode and backupCode")
        
        return attrs


class BackupCodesRegenerateSerializer(serializers.Serializer):
    """
    Serializer for regenerating backup codes.
    """
    verificationCode = serializers.CharField(max_length=6, required=False)
    backupCode = serializers.CharField(max_length=8, required=False)
    method = serializers.CharField(required=False)
    
    def validate(self, attrs):
        """Validate that either verification code or backup code is provided"""
        if not attrs.get('verificationCode') and not attrs.get('backupCode'):
            raise serializers.ValidationError("Either verificationCode or backupCode must be provided")
        
        if attrs.get('verificationCode') and attrs.get('backupCode'):
            raise serializers.ValidationError("Cannot provide both verificationCode and backupCode")
        
        return attrs


class BackupCodesRegenerateResponseSerializer(serializers.Serializer):
    """
    Serializer for backup codes regeneration response.
    """
    backupCodes = serializers.ListField(child=serializers.CharField())
    previousCodesInvalidated = serializers.BooleanField()


class BackupCodesStatusSerializer(serializers.Serializer):
    """
    Serializer for backup codes status response.
    """
    remainingCodes = serializers.IntegerField()
    totalCodes = serializers.IntegerField()
    lastUsed = serializers.DateTimeField(allow_null=True)


class TOTPSetupSerializer(serializers.Serializer):
    """
    Serializer for TOTP setup.
    """
    pass  


class TOTPSetupResponseSerializer(serializers.Serializer):
    """
    Serializer for TOTP setup response.
    """
    setupToken = serializers.CharField()
    qrCodeUrl = serializers.CharField()
    secret = serializers.CharField()
    expiresIn = serializers.IntegerField()
    method = serializers.CharField()


class TOTPVerifySetupSerializer(serializers.Serializer):
    """
    Serializer for verifying TOTP setup.
    """
    setupToken = serializers.CharField()
    verificationCode = serializers.CharField(max_length=6)
    
    def validate_setupToken(self, value):
        """Validate setup token"""
        try:
            user_profile = UserProfile.objects.get(mfa_setup_token=value)
            if not user_profile.is_setup_token_valid():
                raise serializers.ValidationError("Setup token has expired")
            return value
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError("Invalid setup token")
    
    def validate_verificationCode(self, value):
        """Validate TOTP code format"""
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Verification code must be 6 digits")
        return value
    
class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request.
    """
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate email exists in system"""

        return value


class PasswordResetVerifySerializer(serializers.Serializer):
    """
    Serializer for password reset verification.
    """
    resetToken = serializers.CharField(max_length=255)
    newPassword = serializers.CharField(min_length=8, write_only=True)
    
    def validate_resetToken(self, value):
        """Validate reset token exists and is not expired"""
        try:
            user_profile = UserProfile.objects.get(password_reset_token=value)
            if not user_profile.is_password_reset_token_valid():
                raise serializers.ValidationError("Reset token has expired")
            return value
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError("Invalid reset token")
    
    def validate_newPassword(self, value):
        """Validate password strength using Django's password validators"""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value
    


