import requests
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenViewBase
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .permissions import IsAdmin, IsModerator, IsStudent
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework.response import Response
from users.custom_permissions import RolePermission
from users.constants import ADMIN_ROLE, MODERATOR_ROLE
from .models import Job, ApiData, UserData
from users.models import User
from rest_framework.permissions import AllowAny
from .serializers import JobSerializer, JobAdminSerializer, CustomTokenObtainSerializer
from rest_framework import serializers

class AdminOnlyView(APIView):
    permission_classes = [RolePermission]

    def get_permissions(self):
        self.permission_classes = [RolePermission(allowed_roles=[ADMIN_ROLE])]
        return super(AdminOnlyView, self).get_permissions()

    def get(self, request, *args, **kwargs):
        return Response({"message": "This is an admin-only view."})


def get_and_save_all_pages(request):
    base_url = 'https://student.tfi.uz/rest/v1/data/student-list'
    token = 'm7x05Ffypq3jBvplaTc54wk7JqNyqqBO'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }
    page = 1
    all_data = []
    saved_count = 0
    while True:
        response = requests.get(f"{base_url}?page={page}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            for item in data['data']['items']:
                if not ApiData.objects.filter(student_id_number=item['student_id_number']).exists():
                    # Создание записей в базе данных
                    ApiData.objects.create(
                        full_name=item['full_name'],
                        short_name=item['short_name'],
                        first_name=item['first_name'],
                        second_name=item['second_name'],
                        third_name=item['third_name'],
                        #birth_date=item['birth_date'],
                        student_id_number=item['student_id_number'],
                        image=item['image'],
                    )
                    all_data.append(item)
                    saved_count += 1
            # Проверка на наличие следующей страницы
            if page >= data['data']['pagination']['pageCount']:
                break
            page += 1
        else:
            return JsonResponse({'error': 'Could not retrieve data'}, status=response.status_code)
    return JsonResponse({'status': 'data saved', 'saved_items': saved_count})






@method_decorator(csrf_exempt, name='dispatch')
class AuthAndFetchDataView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Получаем логин и пароль от клиента
        login = request.data.get('login')
        password = request.data.get('password')
        print(request.data)

        if not login or not password:
            return Response({'error': 'Login and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Аутентифицируемся на проекте A и получаем токен
        token = self.get_token_from_project_a(login, password)
        print(token)
        if token:
            # Отправляем токен на проект A и получаем данные
            new_data = self.get_data_from_project_a(token)

            # Проверяем данные на дубликаты
            if not self.check_for_duplicates(new_data):
                # Сохраняем данные и логин/пароль
                self.save_user_data(login, password, new_data)

                # Создаем JWT токены
                jwt_tokens = self.create_jwt_token(login)

                if jwt_tokens:
                    return Response({
                        "message": "Data saved successfully.",
                        "jwt_tokens": jwt_tokens
                    })
                else:
                    return Response({"message": "User data not found."}, status=400)
            else:
                return Response({"message": "Duplicate data found."}, status=400)
        else:
            return Response({"message": "Authentication failed."}, status=401)

    def get_token_from_project_a(self, login, password):
        url = "https://student.tfi.uz/rest/v1/auth/login"
        payload = {
            "login": login,
            "password": password
        }
        headers = {
            'accept': "application/json",
            'Content-Type': "application/json"
        }
        print(payload)

        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.status_code == 200:
                return response.json()['data']['token']
            else:
                return None
        except requests.RequestException as e:
            print(f"Error during request: {e}")
            return None

    def get_data_from_project_a(self, token):
        url = "https://student.tfi.uz/rest/v1/account/me"
        headers = {
            "Authorization": f"Bearer {token}"
        }

        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                print(data)
                return data

            else:
                response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error during request: {e}")
            return None

    def check_for_duplicates(self, new_data):
        existing_data = User.objects.values_list('username', flat=True)
        return new_data.get('username') in existing_data

    def save_user_data(self, login, password, new_data):
        hashed_password = make_password(password)

        user, created = User.objects.get_or_create(username=login, defaults={'password': hashed_password})
        if not created:
            user.password = hashed_password
            user.save()

        if 'data' in new_data and 'items' in new_data['data']:
            for item in new_data['data']['items']:
                if not User.objects.filter(student_id_number=item['student_id_number']).exists():
                    # Сохранение данных в кастомную модель пользователя
                    user.full_name = item['full_name']
                    user.short_name = item['short_name']
                    user.first_name = item['first_name']
                    user.second_name = item['second_name']
                    user.third_name = item['third_name']
                    user.student_id_number = item['student_id_number']
                    user.image = item['image']
                    user.save()
                else:
                    print(f"Duplicate found: {item['student_id_number']}")
    def create_jwt_token(self, login):
        try:
            user = User.objects.get(username=login)
            refresh = RefreshToken.for_user(user)
            return {
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }
        except User.DoesNotExist:
            return None

class JobView(generics.ListCreateAPIView):
    queryset = Job.objects.all()
    serializer_class = JobSerializer
    permission_classes = [IsAuthenticated]

class JobView1(generics.ListAPIView):
    queryset = Job.objects.filter(status_admin=True)
    serializer_class = JobAdminSerializer


class CustomTokenObtainPairView(TokenViewBase):
    serializer_class = CustomTokenObtainSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        print(serializer)
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)