from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated,IsAdminUser
from .serializers import OTPSendSerializer,AccountCreateSerializer,UserLoginSerializer,UserForgetPasswordSerializer
from .models import User,AUTH_OTP
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .utils import send_otp_mail
from rest_framework_simplejwt.tokens import AccessToken,RefreshToken
from django.conf import settings
from django.contrib.auth import authenticate
from datetime import timedelta
import requests
class AuthOtpView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = OTPSendSerializer(data=request.data)
        if serializer.is_valid():
            otp_type = serializer.validated_data['otp_type']
            email = serializer.validated_data['email']

            if otp_type == "create_account":
                user = User.objects.filter(email=email).first()
                if user:
                    return Response({
                        "message": "Account with this email already exists."
                    }, status=status.HTTP_406_NOT_ACCEPTABLE)

            elif otp_type == "forget_password":
                user = User.objects.filter(email=email).first()
                if not user:
                    return Response({
                        "message": "Account with this email doesn't exist."
                    }, status=status.HTTP_404_NOT_FOUND)

            try:
                otp_value = send_otp_mail(email=email, otp_type=otp_type)
                otp = AUTH_OTP(
                    otp_value=otp_value,
                    email=email,
                    otp_type=otp_type,
                    created_at=timezone.now()
                )
                otp.save()
                return Response({
                    "message": "OTP sent successfully."
                }, status=status.HTTP_200_OK)
            except Exception as e:
                print("Error:", e)
                return Response({
                    "message": "An error occurred while sending the OTP."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

  
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                 
                      

class UserSignupView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = AccountCreateSerializer(data=request.data)
        if serializer.is_valid():
            account_type=serializer.validated_data['account_type']
            if account_type=="email":
               otp_value = serializer.validated_data['otp_value']
               email = serializer.validated_data['email']
               try:
                  otp_instance = AUTH_OTP.objects.get(
                      otp_value=otp_value,
                      email=email,
                      otp_type="create_account"
                  )
  
                  time_difference = timezone.now() -   otp_instance.created_at
                  if time_difference.total_seconds() > 300:  # 5 minutes
                    return Response({"message": "OTP expired"}, status=status.HTTP_401_UNAUTHORIZED)

                  user = serializer.save()
                  user.set_password(serializer.validated_data  ['password'])
                  user.save()
  
                  access_token = AccessToken.for_user(user)
                  refresh_token = RefreshToken.for_user(user)
  
                  response = Response({
                      "message": "Signup successfully..."
                  }, status=status.HTTP_200_OK)
  
                  response.set_cookie('access_token', str  (access_token), httponly=True,   samesite='Lax', secure=True)
                  response.set_cookie('refresh_token', str  (refresh_token), httponly=True,   samesite='Lax', secure=True)
  
                  return response
               except AUTH_OTP.DoesNotExist:
                 return Response({"message": "Invalid OTP"}, status=status.HTTP_401_UNAUTHORIZED)
            elif account_type == "google":
                # verify the token id and create use
                id_token=request.data.get("id_token")
                if not id_token:
                    return Response({
                        "message":"Missing id token"
                    },status=status.HTTP_400_BAD_REQUEST)
                try:
                    response=request.get(settings.GOOGLE_TOKEN_INFO_URL,params={"id_token":id_token},timeout=5)
                    if(response.status_code!=200):
                        return Response({
                            "message":"Invalid token"
                        },status=status.HTTP_401_UNAUTHORIZED)
                    email=serializer.validated_data['email']
                    user=User.objects.filter(email=email,account_type="google").first()
                    if user:
                        access_token=AccessToken.for_user(user)
                        refresh_token=RefreshToken.for_user(user)
                        response=Response({
                            "message":"Google login successfully"
                        },status=status.HTTP_200_OK)
                        response.set_cookie('access_token', str(access_token), httponly=True,samesite='Lax', secure=True)
                        response.set_cookie('refresh_token', str(refresh_token), httponly=True,samesite='Lax', secure=True)
                        return response
                    user=serializer.save()
                    access_token = AccessToken.for_use(user)
                    refresh_token = RefreshToken.for_user(user)
                    response = Response({"message": "Google signup successful"}, status=status.HTTP_200_OK)
                    response.set_cookie('access_token', str(access_token), httponly=True, samesite='Lax',secure=True)
                    response.set_cookie('refresh_token', str(refresh_token), httponly=True, samesite='Lax',secure=True)
                    return response        
                except requests.RequestException:
                  return Response({"message": "Failed to verify token with Google"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                "message":"all fields are required.."
            },status=status.HTTP_406_NOT_ACCEPTABLE)
             
class UserLoginView(APIView):
    permission_classes=[AllowAny]
    def post(self,request):
         serializer=UserLoginSerializer(data=request.data)
         if(serializer.is_valid()):
              password=serializer.validated_data['password']
              email=serializer.validate_data['email']
              user=authenticate(request,email=email,password=password)
              if user is not None:
                   access_token=AccessToken.for_user(user)
                   refresh_token=RefreshToken.for_user(user)
                   response=Response({
                       "message":"Login successfully",
                       "is_admin":user.is_admin,
                       "access_token":str(access_token),
                       "refresh_token":str(refresh_token),
                   },status=status.HTTP_200_OK)          
                   response.set_cookie(
                            'access_token', str(access_token),
                            max_age=3600,
                            path=settings.AUTH_COOKIE_PATH,
                            secure=False,
                            httponly=True,
                            samesite='Lax'
                        ) 
                   response.set_cookie(
                            'refresh_token', str(refresh_token),
                            max_age=3600,
                            path=settings.AUTH_COOKIE_PATH,
                            secure=False,
                            httponly=True,
                            samesite='Lax'
                        )   
                   return response 
         else:
            return Response({
                "message":serializer.errors
            },status=status.HTTP_401_UNAUTHORIZED)           

class UserForgetPasswordView(APIView):
    permission_classes=[AllowAny]
    def post(self, request):
        serializer = UserForgetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_value = serializer.validated_data['otp_value']
            new_password = serializer.validated_data['new_password']

            # 1. Check if OTP instance exists
            otp_instance = AUTH_OTP.objects.filter(email=email, otp_value=otp_value,otp_type="forget_password").first()
            if not otp_instance:
                return Response({"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

            # 2. Check if OTP is expired (more than 5 minutes old)
            if timezone.now() - otp_instance.created_at > timedelta(minutes=5):
                otp_instance.delete()  # Optional: delete expired OTP
                return Response({"message": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

            # 3. Update the password
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            user.set_password(new_password)
            user.save()

            # 4. Clean up used OTP
            otp_instance.delete()

            return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)                              
    
class GoogleTokenVerificationApiView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        id_token = request.data.get('id_token')

        if not id_token:
            return Response({"message": "Missing id_token"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            response = requests.get(
                settings.GOOGLE_TOKEN_INFO_URL,
                params={"id_token": id_token},
                timeout=5  
            )

            if response.status_code != 200:
                return Response({"message": "Invalid token"}, status=status.HTTP_406_NOT_ACCEPTABLE)

            token_info = response.json()

          
            expected_audience = settings.GOOGLE_CLIENT_ID
            if token_info.get("aud") != expected_audience:
                return Response({"message": "Invalid audience"}, status=status.HTTP_403_FORBIDDEN)

            return Response({
                "message": "Token is valid",
                "token_info": token_info  # optionally return token info
            }, status=status.HTTP_200_OK)

        except requests.exceptions.RequestException as e:
            return Response({"message": "Network error verifying token"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        except Exception as e:
            return Response({"message": "Unexpected error verifying token"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)         
              
          
                                       