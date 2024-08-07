from rest_framework import serializers
from .models import *
from users.models import User
from django.contrib.auth.hashers import check_password


class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = (
            'name',
            'resident',
            'start_data',
            'end_data',
            'discribe',
            'salary',
            'work_time',
            'status',
            'organization',
            'view_count',
        )
class JobAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = (
            'name',
            'resident',
            'start_data',
            'end_data',
            'discribe',
            'salary',
            'work_time',
            'status',
            'organization',
            'view_count',
        )


class NewSerializer(serializers.ModelSerializer):
    class Meta:
        model = New
        fields = (
            'title',
            'discribe',
            'show_data'
        )


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = (
            'title',
            'discribe',
            'begin_date',
            'end_date',
            'status'
        )


class RezumeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rezume
        fields = '__all__'


class CustomTokenObtainSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            try:
                user_data = UserData.objects.get(username=username)
                user = user_data.users
            except UserData.DoesNotExist:
                raise serializers.ValidationError("Invalid username or password")

            if not check_password(password, user_data.password):
                raise serializers.ValidationError("Invalid username or password")
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'")

        data['user'] = user
        return data