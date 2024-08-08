from django.db import models

import random
import uuid
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator, FileExtensionValidator
from rest_framework_simplejwt.tokens import RefreshToken
from .constants import USER_ROLE, MODERATOR_ROLE, ADMIN_ROLE, ROLES


class BaseModel(models.Model):
    """
    - Bu model har doim id, created_at va updated_at fieldlarni qayta yozmasdan har qanday modelda inherit qilib ishlash imkonini beruvchi class.

    - Bu class modelda yaratilmaydi sababi abstract=True deyilgani uchun.

    - Demak, qayta qayta yuqoridagi filedlarni yozmaslik uchun ishlab chiqilgan model

    """
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


MALE, FEMALE = (
    "male",
    "female"
)

NEW, CODE_VERIFIED, DONE, FULL_DONE = (
    "NEW",
    "CODE_VERIFIED",
    "DONE",
    "FULL_DONE"
)

PHONE_EXPIRE = 2


class UserManager(BaseUserManager):

    def _create_user(self, phone_number, password, is_staff=False, is_superuser=False, **extra_fields):
        if not phone_number:
            raise ValueError('Foydalanuvchilar telefon raqami saqlanishi shart')
        user, created = self.model.objects.get_or_create(
            phone_number=phone_number,
            defaults={
                'is_staff': is_staff,
                'is_active': True,
                'is_superuser': is_superuser,
                'last_login': timezone.now(),
                'date_joined': timezone.now(),
                **extra_fields
            }
        )
        if created:
            user.set_password(password)
            user.save(using=self._db)
        return user

    def create_user(self, phone_number, password, **extra_fields):
        return self._create_user(phone_number, password, False, False, **extra_fields)

    def create_superuser(self, phone_number, password, **extra_fields):
        user = self._create_user(phone_number, password, True, True, **extra_fields)
        user.role = 'admin'
        user.auth_status = FULL_DONE
        user.save(using=self._db)
        return user


class User(AbstractUser, BaseModel):
    _validate_phone = RegexValidator(
        regex=r"^998([3578]{2}|(9[013-57-9]))\d{7}$",
        message="Your phone number must start with 9 and not exceed 12 characters. For example: 998901234567",
    )

    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (DONE, DONE),
        (FULL_DONE, FULL_DONE)
    )
    SEX_CHOICES = (
        (MALE, MALE),
        (FEMALE, FEMALE)
    )

    username = models.CharField(max_length=100, null=True)
    full_name = models.CharField(max_length=100, null=True)
    short_name = models.CharField(max_length=100, null=True)
    first_name = models.CharField(max_length=100, null=True)
    second_name = models.CharField(max_length=100, null=True)
    third_name = models.CharField(max_length=100, null=True)
    birth_date = models.PositiveBigIntegerField(default=0, null=True)
    student_id_number = models.CharField(max_length=100, null=True, unique=True)
    auth_status = models.CharField(max_length=31, choices=AUTH_STATUS, default=NEW)
    gender = models.CharField(max_length=20, choices=SEX_CHOICES)
    phone_number = models.CharField(max_length=12, unique=True, validators=[_validate_phone])
    another_number = models.CharField(max_length=12, validators=[_validate_phone], null=True, blank=True)
    pass_address_location = models.CharField(max_length=255)
    role = models.CharField(max_length=9, choices=ROLES, default=USER_ROLE)
    image = models.CharField(max_length=250, null=True)

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []
    objects = UserManager()

    def __str__(self):
        return self.first_name

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def create_verify_code(self):
        code = "".join([str(random.randint(0, 100) % 10) for _ in range(6)])
        print(f'{code=}')
        try:
            confirmation = UserConfirmation.objects.get(user_id=self.id)
            confirmation.code = code
            confirmation.save()
        except UserConfirmation.DoesNotExist:
            UserConfirmation.objects.create(user_id=self.id, code=code)

        return code

    def check_pass(self):
        if not self.password:
            temp_password = f"password{uuid.uuid4().__str__().split('-')[-1]}"
            self.password = temp_password

    def check_first_name(self):
        if not self.first_name:
            temp_first_name = f"first_name_{uuid.uuid4().__str__().split('-')[-1]}"
            self.first_name = temp_first_name

    def check_last_name(self):
        if not self.last_name:
            temp_last_name = f"last_name_{uuid.uuid4().__str__().split('-')[-1]}"
            self.last_name = temp_last_name

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh_token": str(refresh)
        }

    def save(self, *args, **kwargs):
        if self.pk:
            self.clean()
        super(User, self).save(*args, **kwargs)

    def clean(self):
        self.check_first_name()
        self.check_last_name()
        self.check_pass()
        self.hashing_password()


class UserConfirmation(models.Model):
    code = models.CharField(max_length=6)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verify_codes')
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        if self.pk:
            self.expiration_time = timezone.now() + timedelta(minutes=PHONE_EXPIRE)
            self.is_confirmed = False
        else:
            self.expiration_time = timezone.now() + timedelta(minutes=PHONE_EXPIRE)
        super(UserConfirmation, self).save(*args, **kwargs)
