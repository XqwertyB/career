from datetime import datetime

from django.core.exceptions import ObjectDoesNotExist
from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.generics import CreateAPIView, UpdateAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from users.serializers import SignUpSerializer, ChangeUserInformation, LogoutSerializer, \
    LoginRefreshSerializer, ResetPasswordSerializer, ForgotPasswordSerializer, GetUserSerializer, \
    ChangeUserInformationTo, LoginSerializer
from .custom_permissions import AuthStatusPermission, GetUserPermission, ChangeProfilEditPermission
from .models import User, DONE, CODE_VERIFIED, NEW, FULL_DONE
#from .utils import send_phone_notification
# LoginSerializer

class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = SignUpSerializer


class VerifyAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user, code = self.request.user, self.request.data.get('code')

        if self.check_verify(user, code):
            return Response(
                data={
                    "success": True,
                    "auth_status": user.auth_status,
                }, status=status.HTTP_200_OK
            )

    @staticmethod
    def check_verify(user, code):
        if not user.is_authenticated:
            raise ValidationError({"status": False, "message": "User is not authenticated"})

        if hasattr(user, 'verify_codes'):
            verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
            if not verifies.exists():
                raise ValidationError({"status": False, "message": "The code is invalid or expired"})

            verifies.update(is_confirmed=True)

            if user.auth_status == NEW:
                user.auth_status = CODE_VERIFIED
                user.save()

            return True
        else:
            raise ValidationError({"status": False, "message": "User does not have the verify_codes attribute"})


class ChangeUserInformationView(UpdateAPIView):
    permission_classes = [IsAuthenticated, AuthStatusPermission, ]
    serializer_class = ChangeUserInformation
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)
        data = {
            'success': True,
            "message": "User updated successfully",
            'auth_status': self.request.user.auth_status,
        }
        return Response(data, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, **kwargs)
        data = {
            'success': True,
            "message": "User updated successfully",
            'auth_status': self.request.user.auth_status,
        }
        return Response(data, status=status.HTTP_200_OK)


class ChangeUserInformationViewEdit(UpdateAPIView):
    permission_classes = [IsAuthenticated, ChangeProfilEditPermission, ]
    serializer_class = ChangeUserInformationTo
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationViewEdit, self).update(request, *args, **kwargs)
        data = {
            'success': True,
            "message": "User updated successfully",
            'auth_status': self.request.user.auth_status,
        }
        return Response(data, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationViewEdit, self).partial_update(request, *args, **kwargs)
        data = {
            'success': True,
            "message": "User updated successfully",
            'auth_status': self.request.user.auth_status,
        }
        return Response(data, status=status.HTTP_200_OK)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer


class LogOutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        if serializer.is_valid(raise_exception=True):
            try:
                refresh_token = self.request.data['refresh']
                token = RefreshToken(refresh_token)
                token.blacklist()
                data = {
                    'success': True,
                    'message': "You are loggout out"
                }
                return Response(data, status=status.HTTP_205_RESET_CONTENT)
            except TokenError:
                return Response(status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny, ]
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)

        if serializer.is_valid(raise_exception=True):
            phone_number = serializer.validated_data.get('phone_number')
            user = serializer.validated_data.get('user')
            if user is not None and user.auth_status in [DONE, FULL_DONE]:
                code = user.create_verify_code()
#                try:
#                    send_phone_notification(phone_number, code)
#                except Exception as e:
#                    print("ERROR:", e)

                return Response(
                    {
                        "success": True,
                        'message': "Verification code sent successfully",
                        "access": user.token()['access'],
                        "refresh": user.token()['refresh_token'],
                        "user_status": user.auth_status,
                    }, status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {
                        "success": False,
                        'message': "User not found or not fully registered",
                        "user_status": user.auth_status,
                    }, status=status.HTTP_404_NOT_FOUND
                )


class VerifyCodeChangePasswordAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user, code = self.request.user, self.request.data.get('code')

        if self.check_verify(user, code):
            return Response(
                data={
                    "success": True,
                    "message": "The code has been verified",
                    "auth_status": user.auth_status,
                }, status=status.HTTP_200_OK
            )

    @staticmethod
    def check_verify(user, code):
        if not user.is_authenticated:
            raise ValidationError({"status": False, "message": "User is not authenticated"})

        if hasattr(user, 'verify_codes'):
            verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
            if not verifies.exists():
                raise ValidationError({"status": False, "message": "The code is invalid or expired"})

            verifies.update(is_confirmed=True)

            return True
        else:
            raise ValidationError({"status": False, "message": "User does not have the verify_codes attribute"})


class ChangePasswordView(UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [IsAuthenticated, ]
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        response = super(ChangePasswordView, self).update(request, *args, **kwargs)
        try:
            user = User.objects.get(id=response.data.get('id'))
        except ObjectDoesNotExist as e:
            raise NotFound(detail='User not found')

        refresh_token = user.token()['refresh_token']
        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response(
            {
                'success': True,
                'message': "Your password has been successfully changed",
            }
        )


class UserDetailView(APIView):
    permission_classes = (IsAuthenticated, GetUserPermission)
    serializer_class = GetUserSerializer

    def get(self, request, *args, **kwargs):
        user = request.user
        if not User.objects.filter(id=user.id).exists():
            return Response(
                {
                    "message": "User not found."
                },
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.serializer_class(user)
        return Response(
            {
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )
