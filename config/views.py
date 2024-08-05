import requests
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .permissions import IsAdmin, IsModerator, IsStudent


from rest_framework.views import APIView
from rest_framework.response import Response
from users.custom_permissions import RolePermission
from users.constants import ADMIN_ROLE, MODERATOR_ROLE
from .models import Job, ApiData


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