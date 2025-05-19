import random
from django.conf import settings
from django.core.mail import send_mail
type=["account activation",'forget password']




def generate_otp():
    return random.randint(100000,999999)

def send_otp_mail(email,otp_type):
    otp=str(generate_otp())
    message=type[0]
    if(otp_type=="create_account"):
        message=type[0]
    else:
        message=type[1]        
    subject=f'Hi {email} your OTP for {message} is {otp} '
    from_email=settings.EMAIL_HOST_USER
    recipient_list=[email]
    send_mail(subject=subject,message=otp,from_email=from_email,recipient_list=recipient_list)
    return otp 
    