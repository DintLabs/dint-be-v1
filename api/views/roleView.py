from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from api.services.role import RoleService

roleService = RoleService()

role_schema = AutoSchema(manual_fields=[
    coreapi.Field(
        "name",
        required=True,
        location="form",
        schema=coreschema.String()
    )
])


class RoleListView(APIView):
    permission_classes = (AllowAny,)
    def get(self, request, format=None):
        """
        List all roles.
        """
        result = roleService.get_all_roles(request, format=None)
        return Response(result, status=status.HTTP_200_OK)


class RoleCreateView(APIView):
    permission_classes = (AllowAny,)
    schema = role_schema

    def post(self, request, format=None):
        """
        Create Role.
        """
        result = roleService.create(request, format=None)
        return Response(result, status=status.HTTP_200_OK)


class RoleDeleteView(APIView):

    def delete(self, request, pk, format=None):
        """
        Delete Existing Role.
        """
        result = roleService.delete(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class RoleUpdateView(APIView):

    schema = role_schema

    def put(self, request, pk, format=None):
        """
        Update Existing Role
        """
        result = roleService.update(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class RoleListWithPaginationView(APIView):

    def post(self, request, format=None):
        """
        Roles with Pagination
        """
        result = roleService.role_pagination_list(request, format=None)
        return Response(result, status=status.HTTP_200_OK)


class RoleDetailView(APIView):

    def get(self, request, pk, format=None):
        """
        Retrieve a Role
        """
        result = roleService.role_detail(request,pk)
        return Response (result, status=status.HTTP_200_OK)