from api.models import Role
from api.serializers.role import RoleSerializer, RoleDetailSerializer
from api.utils import CustomPagination
from rest_framework import status
from api.utils.messages.commonMessages import *
from api.utils.messages.roleMessages import *

from .roleBaseService import RoleBaseService


class RoleService (RoleBaseService):
    """
    Create, Retrieve, Update or Delete a zone instance and Return all zones.
    """

    def __init__(self):
        pass

    def get_all_roles(self, request, format=None):
        """
        Retun all the role Excluding Role id 4.
        """
        roles = Role.objects.exclude(id__in=[1])
        serializer = RoleDetailSerializer (roles, many=True)
        return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": OK})

    def create(self, request, format=None):
        """
        Create New role And check if same name role is existing in the database then return the error. and after creating the roll all permission is assigned automatically. 
        """
        role = self.get_object_by_name (request.data.get ('name'))
        if role:
            error = {"name": ROLE_NAME_ALREADY_EXIST}
            return ({"data": error, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

        else:
            serializer = RoleSerializer (data=request.data)
            if serializer.is_valid ():
                serializer.save ()
                # Assign user Permission to new Role.
                role = Role.objects.get (id=serializer.data.get ('id'))
                # self.assign_permission (role)

                return ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": ROLE_CREATED})

            return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})

    # def assign_permission(self, role):
    #     """
    #     Assign the user Permission to new role.
    #     """
    #     user_permission_instance = UserPermission.objects.create (role=role)

    #     module_name = ModuleName.objects.all ()
    #     for module in module_name:
    #         user_permission_module_instance = UserPermissionModule.objects.create (
    #             user_permission=user_permission_instance, module_id=module)
    #         module_actions = ModuleAction.objects.filter (module=module)
    #         for actions in module_actions:
    #             user_permission_action_instance = UserPermissionAction.objects.create (
    #                 module=user_permission_module_instance, module_action_id=actions, status=False)

    #     return SUCCUSS

    def delete(self, request, pk, format=None):
        """
        Delete Method.
        """
        role = self.get_object (pk)
        if role:
            if role.can_delete is True:
                role.delete ()
                return ({"code": status.HTTP_200_OK, "message": ROLE_DELETED})
            else:
                return ({"code":status.HTTP_400_BAD_REQUEST, "message":ROLE_CANNOT_BE_DELETE})
        return ({"code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

    def get_object(self, pk):
        """
        Get object by Id
        """
        try:
            return Role.objects.get (id=pk)
        except Role.DoesNotExist:
            None

    def get_object_by_name(self, name):
        """
        Get Object by Name and full_name.
        """
        try:
            return Role.objects.get (name=name)

        except Role.DoesNotExist:
            None

    def role_pagination_list(self, request, format=None):
        """
        returns paginated list of all Roles
        """
        custom_pagination = CustomPagination ()
        search_keys = ['name__icontains', 'id__contains']
        search_type = 'or'
        roles = Role.objects.filter(is_deleted=False)
        roles_response = custom_pagination.custom_pagination(request, Role, search_keys, search_type, RoleDetailSerializer, roles)
        return {"data": roles_response['response_object'],
                "recordsTotal": roles_response['total_records'],
                "recordsFiltered": roles_response['total_records'],
                "code": status.HTTP_200_OK, "message": OK}

    def update(self, request, pk, format=None):
        """
        Updates Role
        """
        data = request.data
        role = self.get_object(pk)
        if role:
            serializer = RoleSerializer(role, data=data)
            if serializer.is_valid ():
                serializer.save ()
                return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": ROLE_UPDATED})
            else:
                return ({"data": serializer.errors, "code": status.HTTP_400_BAD_REQUEST, "message": BAD_REQUEST})
        else:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})

    def role_detail(self, request, pk, format=None):
        """
        Retrieve a Role
        """
        role = self.get_object(pk)
        if role:
            serializer = RoleDetailSerializer(role)
            return ({"data": serializer.data, "code": status.HTTP_200_OK, "message": OK})
        else:
            return ({"data": None, "code": status.HTTP_400_BAD_REQUEST, "message": RECORD_NOT_FOUND})
