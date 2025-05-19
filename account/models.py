from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.utils import timezone


class UserManager(BaseUserManager):
    def create_user(self, name, email, terms_and_condition, password=None, profile_picture=None,account_type='email'):
        if not email:
            raise ValueError("User must have an email address.")
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            name=name,
            terms_and_condition=terms_and_condition,
            profile_picture=profile_picture,
            account_type=account_type
        )
        
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, name, email, password=None):
        user = self.create_user(
            name=name,
            email=email,
            terms_and_condition=True,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    ACCOUNT_TYPE_CHOICES = [
        ('email', 'Email'),
        ('google', 'Google'),
        ('facebook', 'Facebook'),
    ]
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=50)
    is_admin = models.BooleanField(default=False)
    terms_and_condition = models.BooleanField(default=False, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    profile_picture = models.ImageField(upload_to='media/profile_picture', blank=True, null=True)
    account_type=models.CharField(max_length=20,choices=ACCOUNT_TYPE_CHOICES,default='email')
    
    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin


class AUTH_OTP(models.Model):  
    OTP_TYPE_CHOICES = [
        ("create_account", "Create Account"),
        ("forget_password", "Forget Password")
    ]

    email = models.EmailField()
    otp_value = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=30, choices=OTP_TYPE_CHOICES, default="create_account")
    created_at = models.DateTimeField(default=timezone.now)
     
    def __str__(self):
        return f"OTP for {self.email} is {self.otp_value}"
