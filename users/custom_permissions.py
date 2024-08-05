from rest_framework import permissions
from .constants import USER_ROLE, MODERATOR_ROLE, ADMIN_ROLE


class AuthStatusPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        user = request.user
        if view.__class__.__name__ == 'ChangeUserInformationView':
            return True if user.auth_status in ['CODE_VERIFIED', 'DONE', 'FULL_DONE'] else False
        else:
            return True if user.auth_status == 'NEW' else False


class ChangeProfilEditPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        user = request.user
        if view.__class__.__name__ == 'ChangeUserInformationViewEdit':
            return True if user.auth_status in ['DONE', 'FULL_DONE'] else False


class GetUserPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        user = request.user
        if view.__class__.__name__ == 'UserDetailView':
            return True if user.auth_status in ['DONE', 'FULL_DONE'] else False


class RolePermission(permissions.BasePermission):
    def __init__(self, allowed_roles=None):
        self.allowed_roles = allowed_roles or [MODERATOR_ROLE]

    def has_permission(self, request, view):
        return request.user.role in self.allowed_roles