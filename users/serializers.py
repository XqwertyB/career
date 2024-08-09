import re

from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken

# from rest_framework.exceptions import ValidationError

from .models import User, UserConfirmation
from .models import NEW, CODE_VERIFIED, DONE, FULL_DONE, MALE, FEMALE
from rest_framework import serializers

from rest_framework.serializers import ValidationError

#from .utils import send_phone_notification


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)

        self.fields['phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            "id",
            "auth_status"
        )
        extra_kwargs = {
            'auth_status': {'read_only': True, 'required': False},
        }



    def validate(self, attrs):
        super(SignUpSerializer, self).validate(attrs)
        data = self.auth_validate(attrs)
        return data
    @staticmethod
    def auth_validate(attrs):
        user_input = attrs.get('phone_number')

        if user_input is None:
            data = {
                'status': False,
                'message': "You must send phone number"
            }
            raise ValidationError(data)

        if len(user_input) < 12 or len(user_input) > 12 or not str(user_input).startswith('998'):
            data = {
                'status': False,
                'message': "A 12-digit number is mandatory, for example 998901234567"
            }
            raise ValidationError(data)
        query = Q(phone_number=user_input) & (
                Q(auth_status=NEW) | Q(auth_status=CODE_VERIFIED)
        )
        if User.objects.filter(query).exists():
            User.objects.get(query).delete()

        query_2 = Q(phone_number=user_input) & (
                Q(auth_status=DONE) | Q(auth_status=FULL_DONE)
        )
        if User.objects.filter(query_2).exists():
            data = {
                "success": False,
                "message": "This phone number is already being used!"
            }
            raise ValidationError(data)

        return attrs

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data


class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    gender = serializers.CharField(write_only=True, required=True)
    another_number = serializers.CharField(write_only=True, required=True)
    pass_address_location = serializers.CharField(write_only=True, required=True)
    birthday = serializers.DateField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        print('data=', data)
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password is None or confirm_password is None:
            raise ValidationError(
                {
                    "status": False,
                    "message": "Password is required"
                }
            )
        if password != confirm_password:
            raise ValidationError(
                {
                    "status": False,
                    "message": "Your password and verification password are not the same"
                }
            )
        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validate_another_number(self, another_number):
        phone_regex = re.compile(r"^998([3578]{2}|(9[013-57-9]))\d{7}$")

        if re.fullmatch(phone_regex, another_number):
            return another_number
        else:
            raise ValidationError(
                {
                    "status": False,
                    "message": "Your phone number must start with 9 and not exceed 12 characters. For example: 998901234567"
                }
            )

    def update(self, instance, validated_data):

        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.gender = validated_data.get('gender', instance.gender)
        instance.another_number = validated_data.get('another_number', instance.another_number)
        instance.pass_address_location = validated_data.get('pass_address_location', instance.pass_address_location)
        instance.birthday = validated_data.get('birthday', instance.birthday)
        instance.password = validated_data.get('password', instance.password)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance

    def to_representation(self, instance):
        data = super(ChangeUserInformation, self).to_representation(instance)
        data.update(instance.token())

        return data


class ChangeUserInformationTo(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=False)
    last_name = serializers.CharField(write_only=True, required=False)
    gender = serializers.CharField(write_only=True, required=False)
    another_number = serializers.CharField(write_only=True, required=False)
    pass_address_location = serializers.CharField(write_only=True, required=False)
    birthday = serializers.DateField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    def validate_another_number(self, another_number):
        phone_regex = re.compile(r"^998([3578]{2}|(9[013-57-9]))\d{7}$")

        if re.fullmatch(phone_regex, another_number):
            return another_number
        else:
            raise ValidationError(
                {
                    "status": False,
                    "message": "Your phone number must start with 9 and not exceed 12 characters. For example: 998901234567"
                }
            )

    def update(self, instance, validated_data):

        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.gender = validated_data.get('gender', instance.gender)
        instance.another_number = validated_data.get('another_number', instance.another_number)
        instance.pass_address_location = validated_data.get('pass_address_location', instance.pass_address_location)
        instance.birthday = validated_data.get('birthday', instance.birthday)
        instance.permanent_address = validated_data.get('permanent_address', instance.permanent_address)
        instance.password = validated_data.get('password', instance.password)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance

    def to_representation(self, instance):
        data = super(ChangeUserInformationTo, self).to_representation(instance)
        data.update(instance.token())

        return data


class LoginSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['phone_number'] = serializers.CharField(required=True)

    def auth_validate(self, data):
        phone_number = data.get('phone_number')  # phone_number
        user = self.get_user(phone_number=phone_number)
        phone_number = user.phone_number
        authentication_kwargs = {
            'phone_number': data['phone_number'],
            'password': data['password']
        }
        current_user = User.objects.filter(phone_number__iexact=phone_number).first()  # None

        if current_user is not None and current_user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError(
                {
                    'success': False,
                    'message': "You are not fully registered!"
                }
            )
        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            raise ValidationError(
                {
                    'success': False,
                    'message': "Sorry, login or password you entered is incorrect. Please check and trg again!"
                }
            )

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, FULL_DONE]:
            raise PermissionDenied(
                {
                    "satatus": False,
                    "message": "You cannot login. You don't have permission"
                }
            )
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        data['is_superuser'] = self.user.is_superuser
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError(
                {
                    "status": False,
                    "message": "No active account found"
                }
            )
        return users.first()


class LoginRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)
        return data


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ResetPasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(min_length=8, required=True, write_only=True)
    confirm_password = serializers.CharField(min_length=8, required=True, write_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'password',
            'confirm_password'
        )

    def validate(self, data):
        user = self.instance
        current_user = user.verify_codes.filter(user_id=user.id).first()

        if not current_user.is_confirmed:
            raise ValidationError(
                {
                    "status": False,
                    "message": "We have sent a confirmation code to your phone number, confirm the code first!"
                }
            )
        else:
            password = data.get('password', None)
            confirm_password = data.get('password', None)
            if password != confirm_password:
                raise ValidationError(
                    {
                        'success': False,
                        'message': "Your passwords do not have the same value"
                    }
                )
            if password:
                validate_password(password)
            return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(ResetPasswordSerializer, self).update(instance, validated_data)


class ForgotPasswordSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super(ForgotPasswordSerializer, self).__init__(*args, **kwargs)
        self.fields['phone_number'] = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        phone_number = attrs.get('phone_number', None)

        if len(phone_number) < 12 or len(phone_number) > 12 or not str(phone_number).startswith('998'):
            data = {
                'status': False,
                'message': "A 12-digit number is mandatory, for example 998901234567"
            }
            raise ValidationError(data)

        if phone_number is None:
            raise ValidationError(
                {
                    "success": False,
                    'message': "It is mandatory to enter a phone number!"
                }
            )
        user = User.objects.filter(Q(phone_number=phone_number))
        if not user.exists():
            data = {
                'status': False,
                'message': "User not found"
            }
            raise ValidationError(data)
        attrs['user'] = user.first()
        return attrs


class GetUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name',  'is_superuser', 'gender', 'phone_number',
                  'another_number',  'pass_address_location',
                  'birthday',   'role']
