from django.urls import path
from .views import UserSignupView,AuthOtpView,UserLoginView,UserForgetPasswordView,GoogleTokenVerificationApiView

urlpatterns=[
    path('signup/',UserSignupView.as_view()),
    path('send_otp/',AuthOtpView.as_view()),
    path('login/',UserLoginView.as_view()),
    path('forgetpassword/',UserForgetPasswordView.as_view()),
    path('verifyToken/',GoogleTokenVerificationApiView.as_view()),
]