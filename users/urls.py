from django.urls import path
from .views import CreateUserView, VerifyAPIView, ChangeUserInformationView, LoginView, LoginRefreshView, LogOutView, \
    ChangePasswordView, ResetPasswordView, VerifyCodeChangePasswordAPIView, UserDetailView, \
    ChangeUserInformationViewEdit
from config.views import *

urlpatterns = [
    path('login/', LoginView.as_view()),
    path('login/refresh/', LoginRefreshView.as_view()),
    path('logout/', LogOutView.as_view()),
    path('signup/', CreateUserView.as_view()),
    path('user/getme/', UserDetailView.as_view()),
    path('code/', VerifyAPIView.as_view()),
    path('change_user_information/', ChangeUserInformationView.as_view()),
    path('change_user_information_edit/', ChangeUserInformationViewEdit.as_view()),
    path('reset-password/', ResetPasswordView.as_view()),
    path('verify-code/password/', VerifyCodeChangePasswordAPIView.as_view()),
    path('change-password/', ChangePasswordView.as_view()),

    path('asdf/', JobView1.as_view()),
    path('sss/', get_and_save_all_pages, name='get_api_data_with_token'),
    path('aaaa/', AuthAndFetchDataView.as_view()),
    path('job-create/', JobView.as_view()),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
]
