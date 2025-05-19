from rest_framework import serializers
from .models import User
import re

import re
from rest_framework import serializers
from .models import User

class AccountCreateSerializer(serializers.ModelSerializer):
    otp_value = serializers.CharField(write_only=True)
    account_type = serializers.ChoiceField(choices=['google', 'facebook', 'email'])

    class Meta:
        model = User
        fields = [
            'name', 'password', 'email', 'profile_picture',
            'terms_and_condition', 'otp_value', 'account_type'
        ]
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
            'email': {'write_only': True},
            'profile_picture': {'required': False, 'allow_null': True},
            'terms_and_condition': {'required': True, 'allow_null': True},
            'otp_value': {'required': True},
        }

    def validate_email(self, value):
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, value):
            raise serializers.ValidationError("Enter a valid email address.")
        return value

    def validate(self, data):
        if not data.get('email'):
            raise serializers.ValidationError({'email': 'Email is required.'})
        if not data.get('name'):
            raise serializers.ValidationError({'name': 'Name is required.'})
        if data['account_type'] == 'email' and not data.get('password'):
            raise serializers.ValidationError({'password': 'Password is required for email signup.'})
        return data

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        otp_value = validated_data.pop('otp_value')  
        account_type = validated_data.get('account_type')

      
        user = User(**validated_data)

        if account_type == 'email':
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save()
        return user



class OTPSendSerializer(serializers.Serializer):
    OTP_TYPE_CHOICES = [
        ("create_account", "Create Account"),
        ("forget_password", "Forget Password")
    ]

    email = serializers.EmailField(required=True)
    otp_type = serializers.ChoiceField(choices=OTP_TYPE_CHOICES, default="create_account")

class UserLoginSerializer(serializers.Serializer):
    email=serializers.EmailField(required=True)
    password=serializers.CharField(required=True,write_only=True)    

class UserForgetPasswordSerializer(serializers.Serializer):
    otp_value = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    new_password = serializers.CharField(required=True, min_length=6, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        if new_password != confirm_password:
            raise serializers.ValidationError({
                "confirm_password": "Passwords do not match."
            })

        if len(new_password) < 6:
            raise serializers.ValidationError({
                "new_password": "Password must be at least 6 characters long."
            })

        return attrs   