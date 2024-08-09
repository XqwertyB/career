from django.contrib.auth.models import AbstractUser
from django.db import models
from users.models import User
from ckeditor.fields import RichTextField


class Job(models.Model):
    TIME = (
        ('part_time', 'Part time'),
        ('full_time', 'Full time'),

    )
    STATUS = (
        ('new', 'Moderatsiyada'),
        ('on_verification', 'Faollashtirildi'),
        ('inactive', 'Faol emas')
    )

    name = models.CharField("Nomi", max_length=50)
    resident = models.CharField("Ish beruvchi", max_length=50)
    start_data = models.DateTimeField("Boshlanish vaqti", auto_now=True)
    end_data = models.DateTimeField("Tugash vaqti", auto_now=True)
    discribe = RichTextField("Ma'lumot")
    salary = models.BooleanField("Holati", default=True)
    work_time = models.CharField("Ish vaqt tartibi", choices=TIME, default='part_time', max_length=20)
    status = models.CharField('Xolati', choices=STATUS, default='new', max_length=20)
    status_admin = models.BooleanField("Admin uchun kurinish statusi", default=False)
    organization = models.CharField('Organizatsiya nomi', max_length=100)
    view_count = models.PositiveIntegerField(default=0)

    def __str__(self):
        return str(self.name)


class New(models.Model):
    title = models.CharField('Nomi', max_length=100)
    discribe = RichTextField("Ma'lumotlari")
    show_data = models.DateTimeField("Sharx vaqti", auto_now=True)

    def __str__(self):
        return self.title


class Event(models.Model):
    title = models.CharField('Nomi', max_length=50)
    discribe = RichTextField("Ma'lumot")
    begin_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField(auto_now=True)
    status = models.BooleanField('Xolati', default=False)

    def __str__(self):
        return self.title


class Rezume(models.Model):
    id = models.CharField(max_length=50, primary_key=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    degree = models.CharField('Ilmiy daraja (Unvon)', max_length=50)

    def __str__(self):
        return str(self.user_id)


class Organization(models.Model):
    name = models.CharField("Korxona nomi", max_length=100)
    inn = models.PositiveIntegerField("INN", )
    describe = RichTextField("Korxona xaqida")
    resprentative = models.ForeignKey(User, on_delete=models.CASCADE)
    phone = models.PositiveIntegerField("Korxonani telefon raqami")

    def __str__(self):
        return self.name


class Wish_list(models.Model):
    user = models.ForeignKey(User, verbose_name="Users", on_delete=models.CASCADE)
    job = models.ForeignKey(Job, verbose_name="Jobs", on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user} - {self.job}"


class ApiData(models.Model):
    full_name = models.CharField(max_length=100)
    short_name = models.CharField(max_length=100)
    first_name = models.CharField(max_length=100)
    second_name = models.CharField(max_length=100)
    third_name = models.CharField(max_length=100)
    birth_date = models.PositiveBigIntegerField(default=0)
    student_id_number = models.PositiveIntegerField(default=0)
    image = models.CharField(max_length=100)

    def __str__(self):
        return self.short_name


class UserData(models.Model):
    users = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)
    data = models.JSONField()