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


