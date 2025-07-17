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
import pyotp
import qrcode
import io
import base64
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
import random
import string
from datetime import datetime, timedelta
from django.utils import timezone



from .serializers import (
    UserRegistrationSerializer, UserResponseSerializer, LoginSerializer, 
    LoginResponseUserSerializer, MFAMethodsSerializer, EmailMFAEnableSerializer,
    MFASetupResponseSerializer, MFAVerifySetupSerializer, MFAVerifySetupResponseSerializer,
    MFAVerifySerializer, MFAVerifyResponseSerializer, MFADisableSerializer,
    BackupCodesRegenerateSerializer, BackupCodesRegenerateResponseSerializer,
    BackupCodesStatusSerializer, TOTPSetupSerializer, TOTPSetupResponseSerializer,
    TOTPVerifySetupSerializer,PasswordResetRequestSerializer, PasswordResetVerifySerializer
)
from .models import UserProfile, MFABackupCode, MFAAttempt


class RegisterView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                user = serializer.save()
                
                response_serializer = UserResponseSerializer(user)
                
                return Response({
                    "success": True,
                    "message": "User registered successfully",
                    "data": response_serializer.data,
                    "errors": None
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response({
                    "success": False,
                    "message": "Registration failed",
                    "data": None,
                    "errors": [{"field": "general", "message": str(e), "code": "REGISTRATION_FAILED"}]
                }, status=status.HTTP_400_BAD_REQUEST)
        
        else:
            errors = []
            for field, messages in serializer.errors.items():
                for message in messages:
                    error_code = "VALIDATION_ERROR"
                    
                    if field == "email" and "already exists" in str(message):
                        error_code = "EMAIL_EXISTS"
                    elif field == "userName" and "already exists" in str(message):
                        error_code = "USERNAME_EXISTS"  
                    elif field == "phoneNumber" and "already exists" in str(message):
                        error_code = "PHONE_EXISTS"
                    
                    api_field = field
                    if field == "userName":
                        api_field = "userName"
                    elif field == "firstName":
                        api_field = "firstName"
                    elif field == "lastName":
                        api_field = "lastName"
                    elif field == "phoneNumber":
                        api_field = "phoneNumber"
                    
                    errors.append({
                        "field": api_field,
                        "message": str(message),
                        "code": error_code
                    })
            
            return Response({
                "success": False,
                "message": "Validation failed",
                "data": None,
                "errors": errors
            }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = None
        
        if '@' in username:
            try:
                user_obj = User.objects.get(email=username)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                pass
        else:
            user = authenticate(username=username, password=password)
        
        if user is None:
            return Response({
                "success": False,
                "message": "Invalid credentials",
                "data": None,
                "errors": None
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.is_active:
            return Response({
                "success": False,
                "message": "Account is disabled",
                "data": None,
                "errors": None
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        user_profile = user.profile
        
        if user_profile.is_mfa_enabled:
            login_token = user_profile.generate_login_token()
            
            available_methods = user_profile.get_available_mfa_methods()
            enabled_methods = user_profile.get_enabled_mfa_methods()
            
            user_serializer = LoginResponseUserSerializer(user)
            
            return Response({
                "success": True,
                "message": "MFA verification required",
                "data": {
                    "requiresMfa": True,
                    "loginToken": login_token,
                    "availableMethods": available_methods,
                    "primaryMethod": user_profile.primary_mfa_method,
                    "expiresIn": 300, 
                    "user": user_serializer.data
                },
                "errors": None
            }, status=status.HTTP_200_OK)
        
        else:
            access_token = AccessToken.for_user(user)
            refresh_token = RefreshToken.for_user(user)
            
            user_serializer = LoginResponseUserSerializer(user)
            
            return Response({
                "success": True,
                "message": "Login successful",
                "data": {
                    "requiresMfa": False,
                    "user": user_serializer.data,
                    "tokens": {
                        "accessToken": str(access_token),
                        "refreshToken": str(refresh_token),
                        "expiresIn": 3600,
                        "tokenType": "Bearer"
                    }
                },
                "errors": None
            }, status=status.HTTP_200_OK)


# MFA Views
class MFAMethodsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get available MFA methods for user"""
        user_profile = request.user.profile
        
        available_methods = user_profile.get_available_mfa_methods()
        enabled_methods = user_profile.get_enabled_mfa_methods()
        
        has_backup_codes = MFABackupCode.get_remaining_codes_count(request.user) > 0
        
        data = {
            "available": available_methods,
            "enabled": enabled_methods,
            "primary": user_profile.primary_mfa_method if user_profile.is_mfa_enabled else None,
            "hasBackupCodes": has_backup_codes
        }
        
        return Response({
            "success": True,
            "message": "MFA methods retrieved",
            "data": data,
            "errors": None
        }, status=status.HTTP_200_OK)


class EmailMFAEnableView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Enable Email MFA for user account"""
        serializer = EmailMFAEnableSerializer(data=request.data, context={'request': request})
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user_profile = request.user.profile
        
        setup_token = user_profile.generate_setup_token('email')
        
        verification_code = str(random.randint(100000, 999999))
        user_profile.otp_code = verification_code
        user_profile.otp_created_at = timezone.now()
        user_profile.save()
        
        try:
            send_mail(
                'MFA Setup Verification',
                f'Your verification code is: {verification_code}',
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],
                fail_silently=False,
            )
        except Exception as e:
            return Response({
                "success": False,
                "message": "Failed to send verification email",
                "data": None,
                "errors": None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            "success": True,
            "message": "Email MFA setup initiated. Verification code sent.",
            "data": {
                "setupToken": setup_token,
                "expiresIn": 300,
                "method": "email"
            },
            "errors": None
        }, status=status.HTTP_200_OK)


class EmailMFAVerifySetupView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Complete Email MFA setup with verification"""
        serializer = MFAVerifySetupSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        setup_token = serializer.validated_data['setupToken']
        verification_code = serializer.validated_data['verificationCode']
        
        try:
            user_profile = UserProfile.objects.get(mfa_setup_token=setup_token)
            
            if not user_profile.is_otp_valid(verification_code):
                return Response({
                    "success": False,
                    "message": "Invalid or expired verification code",
                    "data": None,
                    "errors": None
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user_profile.is_mfa_enabled = True
            user_profile.primary_mfa_method = 'email'
            user_profile.mfa_setup_token = None
            user_profile.mfa_setup_token_created_at = None
            user_profile.mfa_setup_method = None
            user_profile.otp_code = None
            user_profile.otp_created_at = None
            user_profile.save()
            
            backup_codes = MFABackupCode.generate_codes_for_user(user_profile.user)
            
            return Response({
                "success": True,
                "message": "Email MFA enabled successfully",
                "data": {
                    "method": "email",
                    "backupCodes": backup_codes
                },
                "errors": None
            }, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({
                "success": False,
                "message": "Invalid setup token",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)


class TOTPSetupView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Setup TOTP MFA for user account"""
        user_profile = request.user.profile
        
        secret = pyotp.random_base32()
        
        setup_token = user_profile.generate_setup_token('totp')
        
        user_profile.mfa_secret = secret
        user_profile.save()
        
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=request.user.email,
            issuer_name="Your App Name"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        qr_code_url = f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"
        
        return Response({
            "success": True,
            "message": "TOTP setup initiated",
            "data": {
                "setupToken": setup_token,
                "qrCodeUrl": qr_code_url,
                "secret": secret,
                "expiresIn": 300,
                "method": "totp"
            },
            "errors": None
        }, status=status.HTTP_200_OK)


class TOTPVerifySetupView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Complete TOTP MFA setup with verification"""
        serializer = TOTPVerifySetupSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        setup_token = serializer.validated_data['setupToken']
        verification_code = serializer.validated_data['verificationCode']
        
        try:
            user_profile = UserProfile.objects.get(mfa_setup_token=setup_token)
            
            totp = pyotp.TOTP(user_profile.mfa_secret)
            if not totp.verify(verification_code):
                return Response({
                    "success": False,
                    "message": "Invalid verification code",
                    "data": None,
                    "errors": None
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user_profile.is_mfa_enabled = True
            user_profile.primary_mfa_method = 'totp'
            user_profile.mfa_setup_token = None
            user_profile.mfa_setup_token_created_at = None
            user_profile.mfa_setup_method = None
            user_profile.save()
            
            backup_codes = MFABackupCode.generate_codes_for_user(user_profile.user)
            
            return Response({
                "success": True,
                "message": "TOTP MFA enabled successfully",
                "data": {
                    "method": "totp",
                    "backupCodes": backup_codes
                },
                "errors": None
            }, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({
                "success": False,
                "message": "Invalid setup token",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)


class MFAVerifyView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Verify MFA code during login or sensitive operations"""
        serializer = MFAVerifySerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        login_token = serializer.validated_data['loginToken']
        verification_code = serializer.validated_data.get('verificationCode')
        backup_code = serializer.validated_data.get('backupCode')
        method = serializer.validated_data.get('method')
        
        try:
            user_profile = UserProfile.objects.get(login_token=login_token)
            user = user_profile.user
            
            verification_success = False
            used_method = method
            
            if backup_code:
                verification_success = MFABackupCode.verify_code(user, backup_code)
                used_method = 'backup'
            elif verification_code:
                if method == 'totp' and user_profile.mfa_secret:
                    totp = pyotp.TOTP(user_profile.mfa_secret)
                    verification_success = totp.verify(verification_code)
                elif method == 'email' or not method:
                    verification_success = user_profile.is_otp_valid(verification_code)
                    used_method = 'email'
            
            MFAAttempt.objects.create(
                user=user,
                method=used_method,
                success=verification_success,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            if not verification_success:
                return Response({
                    "success": False,
                    "message": "Invalid verification code",
                    "data": None,
                    "errors": None
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user_profile.login_token = None
            user_profile.login_token_created_at = None
            user_profile.otp_code = None
            user_profile.otp_created_at = None
            user_profile.save()
            
            access_token = AccessToken.for_user(user)
            refresh_token = RefreshToken.for_user(user)
            
            user_serializer = LoginResponseUserSerializer(user)
            
            return Response({
                "success": True,
                "message": "MFA verification successful",
                "data": {
                    "user": user_serializer.data,
                    "tokens": {
                        "accessToken": str(access_token),
                        "refreshToken": str(refresh_token),
                        "expiresIn": 3600,
                        "tokenType": "Bearer"
                    }
                },
                "errors": None
            }, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({
                "success": False,
                "message": "Invalid login token",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)


class MFASendOTPView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        login_token = request.data.get('loginToken')
        method = request.data.get('method')
        
        if not login_token:
            return Response({
                "success": False,
                "message": "Login token is required",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not method:
            return Response({
                "success": False,
                "message": "Method is required",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user_profile = UserProfile.objects.get(login_token=login_token)
            user = user_profile.user
            
            if method == 'email':
                otp_code = ''.join(random.choices(string.digits, k=6))
                
                user_profile.otp_code = otp_code
                user_profile.otp_created_at = timezone.now()
                user_profile.save()
                
                try:
                    send_mail(
                        subject='Your MFA Verification Code',
                        message=f'Your verification code is: {otp_code}\n\nThis code will expire in 5 minutes.',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                    
                    return Response({
                        "success": True,
                        "message": "OTP sent successfully to your email",
                        "data": None,
                        "errors": None
                    }, status=status.HTTP_200_OK)
                    
                except Exception as e:
                    return Response({
                        "success": False,
                        "message": "Failed to send email. Please try again.",
                        "data": None,
                        "errors": None
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            elif method == 'totp':
                return Response({
                    "success": False,
                    "message": "TOTP codes are generated by your authenticator app",
                    "data": None,
                    "errors": None
                }, status=status.HTTP_400_BAD_REQUEST)
            
            else:
                return Response({
                    "success": False,
                    "message": "Invalid method specified",
                    "data": None,
                    "errors": None
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except UserProfile.DoesNotExist:
            return Response({
                "success": False,
                "message": "Invalid login token",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "success": False,
                "message": "An error occurred while sending OTP",
                "data": None,
                "errors": None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class MFADisableView(APIView):
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        """Disable MFA (requires MFA verification)"""
        serializer = MFADisableSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user_profile = request.user.profile
        verification_code = serializer.validated_data.get('verificationCode')
        backup_code = serializer.validated_data.get('backupCode')
        method = serializer.validated_data.get('method')
        
        verification_success = False
        
        if backup_code:
            verification_success = MFABackupCode.verify_code(request.user, backup_code)
        elif verification_code:
            if method == 'totp' and user_profile.mfa_secret:
                totp = pyotp.TOTP(user_profile.mfa_secret)
                verification_success = totp.verify(verification_code)
            elif method == 'email' or not method:
                if not user_profile.otp_code:
                    otp = str(random.randint(100000, 999999))
                    user_profile.otp_code = otp
                    user_profile.otp_created_at = timezone.now()
                    user_profile.save()
                    
                    try:
                        send_mail(
                            'MFA Disable Verification',
                            f'Your verification code is: {otp}',
                            settings.DEFAULT_FROM_EMAIL,
                            [request.user.email],
                            fail_silently=False,
                        )
                    except:
                        pass
                    
                    return Response({
                        "success": False,
                        "message": "Verification code sent to your email",
                        "data": None,
                        "errors": None
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                verification_success = user_profile.is_otp_valid(verification_code)
        
        if not verification_success:
            return Response({
                "success": False,
                "message": "Invalid verification code",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user_profile.is_mfa_enabled = False
        user_profile.mfa_secret = None
        user_profile.primary_mfa_method = 'totp'
        user_profile.otp_code = None
        user_profile.otp_created_at = None
        user_profile.save()
        
        MFABackupCode.objects.filter(user=request.user).delete()
        
        return Response({
            "success": True,
            "message": "MFA disabled successfully",
            "data": None,
            "errors": None
        }, status=status.HTTP_200_OK)


class BackupCodesRegenerateView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Generate new backup codes (requires MFA verification)"""
        serializer = BackupCodesRegenerateSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user_profile = request.user.profile
        verification_code = serializer.validated_data.get('verificationCode')
        backup_code = serializer.validated_data.get('backupCode')
        method = serializer.validated_data.get('method')
        
        verification_success = False
        
        if backup_code:
            verification_success = MFABackupCode.verify_code(request.user, backup_code)
        elif verification_code:
            if method == 'totp' and user_profile.mfa_secret:
                totp = pyotp.TOTP(user_profile.mfa_secret)
                verification_success = totp.verify(verification_code)
            elif method == 'email' or not method:
                if not user_profile.otp_code:
                    otp = str(random.randint(100000, 999999))
                    user_profile.otp_code = otp
                    user_profile.otp_created_at = timezone.now()
                    user_profile.save()
                    
                    try:
                        send_mail(
                            'Backup Codes Regeneration Verification',
                            f'Your verification code is: {otp}',
                            settings.DEFAULT_FROM_EMAIL,
                            [request.user.email],
                            fail_silently=False,
                        )
                    except:
                        pass
                    
                    return Response({
                        "success": False,
                        "message": "Verification code sent to your email",
                        "data": None,
                        "errors": None
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                verification_success = user_profile.is_otp_valid(verification_code)
        
        if not verification_success:
            return Response({
                "success": False,
                "message": "Invalid verification code",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        backup_codes = MFABackupCode.generate_codes_for_user(request.user)
        
        user_profile.otp_code = None
        user_profile.otp_created_at = None
        user_profile.save()
        
        return Response({
            "success": True,
            "message": "Backup codes regenerated",
            "data": {
                "backupCodes": backup_codes,
                "previousCodesInvalidated": True
            },
            "errors": None
        }, status=status.HTTP_200_OK)


class BackupCodesView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """View remaining backup codes"""
        remaining_codes = MFABackupCode.get_remaining_codes_count(request.user)
        total_codes = MFABackupCode.objects.filter(user=request.user).count()
        last_used = MFABackupCode.get_last_used_date(request.user)
        
        return Response({
            "success": True,
            "message": "Backup codes retrieved",
            "data": {
                "remainingCodes": remaining_codes,
                "totalCodes": total_codes,
                "lastUsed": last_used
            },
            "errors": None
        }, status=status.HTTP_200_OK)
    



class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Request password reset - sends email with reset link"""
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Invalid input",
                "data": None,
                "errors": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            user_profile = user.profile
            
            reset_token = user_profile.generate_password_reset_token()
            
            reset_link = f"{settings.FRONTEND_URL}/auth/password-reset?token={reset_token}"
            
            subject = "Password Reset Request"
            
            html_message = f"""
            <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>Hello {user.first_name or user.username},</p>
                <p>You requested to reset your password. Click the link below to reset your password:</p>
                <p><a href="{reset_link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                <p>This link will expire in 15 minutes.</p>
                <p>If you didn't request this password reset, please ignore this email.</p>
                <p>Best regards,<br>Your App Team</p>
            </body>
            </html>
            """
            
            plain_message = f"""
            Password Reset Request
            
            Hello {user.first_name or user.username},
            
            You requested to reset your password. Click the link below to reset your password:
            {reset_link}
            
            This link will expire in 15 minutes.
            
            If you didn't request this password reset, please ignore this email.
            
            Best regards,
            Your App Team
            """
            
            try:
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    html_message=html_message,
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Email sending failed: {e}")
                
        except User.DoesNotExist:
            pass
        
        return Response({
            "success": True,
            "message": "Password reset email sent if account exists",
            "data": None,
            "errors": None
        }, status=status.HTTP_200_OK)


class PasswordResetVerifyView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Verify password reset token and set new password"""
        serializer = PasswordResetVerifySerializer(data=request.data)
        
        if not serializer.is_valid():
            errors = []
            for field, messages in serializer.errors.items():
                for message in messages:
                    error_code = "VALIDATION_ERROR"
                    
                    if field == "resetToken":
                        if "expired" in str(message):
                            error_code = "TOKEN_EXPIRED"
                        elif "Invalid" in str(message):
                            error_code = "INVALID_TOKEN"
                    elif field == "newPassword":
                        error_code = "WEAK_PASSWORD"
                    
                    errors.append({
                        "field": field,
                        "message": str(message),
                        "code": error_code
                    })
            
            return Response({
                "success": False,
                "message": "Validation failed",
                "data": None,
                "errors": errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        reset_token = serializer.validated_data['resetToken']
        new_password = serializer.validated_data['newPassword']
        
        try:
            user_profile = UserProfile.objects.get(password_reset_token=reset_token)
            user = user_profile.user
            
            if not user_profile.is_password_reset_token_valid():
                return Response({
                    "success": False,
                    "message": "Reset token has expired",
                    "data": None,
                    "errors": [{"field": "resetToken", "message": "Reset token has expired", "code": "TOKEN_EXPIRED"}]
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user.password = make_password(new_password)
            user.save()
            
            user_profile.clear_password_reset_token()
            
            try:
                send_mail(
                    subject="Password Reset Successful",
                    message=f"""
                    Hello {user.first_name or user.username},
                    
                    Your password has been successfully reset.
                    
                    If you didn't make this change, please contact our support team immediately.
                    
                    Best regards,
                    Your App Team
                    """,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=True,
                )
            except:
                pass
            
            return Response({
                "success": True,
                "message": "Password reset successful",
                "data": None,
                "errors": None
            }, status=status.HTTP_200_OK)
            
        except UserProfile.DoesNotExist:
            return Response({
                "success": False,
                "message": "Invalid reset token",
                "data": None,
                "errors": [{"field": "resetToken", "message": "Invalid reset token", "code": "INVALID_TOKEN"}]
            }, status=status.HTTP_400_BAD_REQUEST)
        



class NewsAPIView(APIView):

    permission_classes = [IsAuthenticated]

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
            response_status_code = None
            try:
                if response is not None:
                    response_status_code = response.status_code
                    news_api_error_json = response.json()
                    news_api_message = news_api_error_json.get('message', 'Unknown external API error')
                    error_detail = f"News API Error ({response_status_code}): {news_api_message}"
            except (AttributeError, ValueError): 
                error_detail = f"Network or unexpected error connecting to News API: {e}"

            return Response(
                {"detail": error_detail},
                status=response_status_code if response_status_code and response_status_code >= 400 else status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response({"detail": f"An unexpected server error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

