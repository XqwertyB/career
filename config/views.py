import requests
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
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
from rest_framework.permissions import AllowAny
from .serializers import JobSerializer, JobAdminSerializer

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


from django.views import View

@method_decorator(csrf_exempt, name='dispatch')
class AuthAndFetchDataView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # Получаем логин и пароль от клиента
        login = request.data['login']
        password = request.data['password']
        print(request.data)
        # try:
        #     user = UserData.objects.get(username=login)
        # except Exception as ex:
        #     return Response(
        #         {'error':'Foydalanuvchi yoq!'},status=status.HTTP_404_NOT_FOUND
        #     )
        # #print(login)

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
                return Response({"message": "Data saved successfully."})
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
        header = {
            'accept':"application/json",
            'Content-Type':"application/json"
        }
        print(payload)

        response = requests.post(url, headers=header, json=payload)
        print(response.status_code)
        if response.status_code == 200:

            return response.json()['data']['token']
        else:
            return None

    def get_data_from_project_a(self, token):
        url = "https://student.tfi.uz/rest/v1/account/me"
        headers = {
            "Authorization": f"Bearer {token}"
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

    def check_for_duplicates(self, new_data):
        existing_data = UserData.objects.values_list('data', flat=True)
        return new_data in existing_data

    def save_user_data(self, login, password, data):
        UserData.objects.create(username=login, password=password, data=data)


class JobView(generics.ListCreateAPIView):
    queryset = Job.objects.all()
    serializer_class = JobSerializer
    permission_classes = [IsAuthenticated]

class JobView1(generics.ListAPIView):
    queryset = Job.objects.filter(status_admin=True)
    serializer_class = JobAdminSerializer


