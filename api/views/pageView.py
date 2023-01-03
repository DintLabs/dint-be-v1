from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.schemas import AutoSchema
from rest_framework.compat import coreapi, coreschema
from api.services.page import PageService

pageService = PageService()

role_schema = AutoSchema(manual_fields=[
    coreapi.Field(
        "name",
        required=True,
        location="form",
        schema=coreschema.String()
    )
])


class ListCreateUpdateDeletePageView(APIView):

    def get(self, request, format=None):
        """
        Retun all the Posts.
        """
        result = pageService.get_page_list(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Create New Posts. 
        """
        result = pageService.create_page(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        """
        Updates Post
        """
        result = pageService.update_page(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, pk,  format=None):
        """
        Delete Posts. 
        """
        result = pageService.delete_page(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)



class GetPagePaginationView(APIView):
    def post(self, request, format=None):
        """
        Retrieve a Post by ID
        """
        result = pageService.get_page_list_with_pagination(request, format=None)
        return Response(result, status=status.HTTP_200_OK)


class GetPageView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = pageService.get_page(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)



class PageByUserIDView(APIView):

    def get(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = pageService.get_pages_by_user_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)


class PagePaginationByUserIDView(APIView):
    
    def post(self, request,pk, format=None):
        """
        Retrieve a Post by ID
        """
        result = pageService.get_pagination_pages_by_user_id(request, pk, format=None)
        return Response(result, status=status.HTTP_200_OK)

class SearchPageView(APIView):
    def post(self, request,format=None):
        """
        Retrieve a Post by ID
        """
        result = pageService.search_page(request, format=None)
        return Response(result, status=status.HTTP_200_OK)

class GetPageByPageNameView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, page_name,format=None):
        """
        Retrieve a Post by ID
        """
        result = pageService.page_by_page_name(request, page_name, format=None)
        return Response(result, status=status.HTTP_200_OK)


class CheckUsernameAvailabilityView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, user_name,format=None):
        """
        Retrieve a Post by ID
        """
        result = pageService.check_username_availability(request, user_name, format=None)
        return Response(result, status=status.HTTP_200_OK)