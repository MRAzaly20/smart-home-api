from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.mixins import UpdateModelMixin, DestroyModelMixin
from django.contrib.auth.hashers import make_password
from rest_framework.generics import CreateAPIView,GenericAPIView, RetrieveUpdateDestroyAPIView, UpdateAPIView
from .models import  Author, Publisher, Customer, Store, Purchase, Book
from django.contrib.auth import authenticate
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from rest_framework import status, views
from django.contrib.auth.models import User
from . import serializers
from .serializers import (TodoSerializer, AuthorSerializer, UserSerializer,
LoginSerializer, PublisherSerializer,
UpdateUserSerializer,UserProfileSerializer, UpdatePassSerializer,
CustomerSerializer, StoreSerializer, BookSerializer, PurchaseSerializer,
LogoutSerializer ,MyTokenObtainPairSerializer)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class MyTokenRefreshView(TokenRefreshView):
    # Anda bisa menambahkan custom logic jika diperlukan
    pass

class RestrictedView(APIView):
  permission = (IsAuthenticated,)
  
  def get(self, request, format=None):
    print(request)
    return JsonResponse({"response":"access granted"})

class UpdatePassView(APIView):
    
    #def put(self, request):
    #queryset = User.objects.all()
    permission = (IsAuthenticated,)
    def put(self, request, *args, **kwargs):
        print(request.user)
        user_id = kwargs.get('pk')
        user = User.objects.get(id=user_id)
        
        # Pastikan bahwa request.user adalah user yang sama dengan yang ingin di-update
        if not user:
            return Response({"authorize": "You don't have permission for this user."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = UpdatePassSerializer(user, data=request.data, context={'user_id': user_id})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UpdateProfileView(APIView):
    
    permission = (IsAuthenticated,)
    def put(self, request, *args, **kwargs):
        print(request.user)
        user_id = kwargs.get('pk')
        user = User.objects.get(id=user_id)
        
        # Pastikan bahwa request.user adalah user yang sama dengan yang ingin di-update
        if not user:
            return Response({"authorize": "You don't have permission for this user."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer_user = UpdateUserSerializer(user, data=request.data, context={'user_id': user_id})
        serializer_custom = UserProfileSerializer(user, data=request.data, context={'user_id': user_id})
        if serializer_user.is_valid() and serializer_custom.is_valid():
            serializer_user.save()
            serializer_custom.save()
            return Response({"message": "Profile updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer_custom.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class RegisterView(views.APIView):
    def post(self, request):
        print(request.data)
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(views.APIView):
    def post(self, request):
        serializer_data = LoginSerializer(data=request.data)
        if serializer_data.is_valid():
            user = serializer_data.validated_data
            print("user :" , user)
            #token = user.auth_token
            return Response({"tokens": user})
        return Response(serializer_data.errors, status=status.HTTP_400_BAD_REQUEST)
        
class LogoutAPIView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
        
class LoginAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        print(user)
        if user:
            return Response(TodoSerializer(user).data)
        return Response(status=status.HTTP_404_NOT_FOUND)

# View untuk User

class TodoCreateView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = TodoSerializer

    def perform_create(self, serializer):
        password = make_password(self.request.data.get('password'))
        serializer.save(password=password)
        
class TodoDetailView(RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    read_serializer = TodoSerializer(queryset, many=True)
    #print(read_serializer.data)
    serializer_class = TodoSerializer

# View untuk Author
class AuthorCreateView(CreateAPIView):
    queryset = Author.objects.all()
    serializer_class = AuthorSerializer

class AuthorDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Author.objects.all()
    serializer_class = AuthorSerializer

# View untuk Publisher
class PublisherCreateView(CreateAPIView):
    queryset = Publisher.objects.all()
    serializer_class = PublisherSerializer

class PublisherDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Publisher.objects.all()
    serializer_class = PublisherSerializer

# View untuk Customer
class CustomerCreateView(CreateAPIView):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer

class CustomerDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    
class StoreCreateView(CreateAPIView):
    queryset = Store.objects.all()
    serializer_class = StoreSerializer

class StoreDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Store.objects.all()
    serializer_class = StoreSerializer
    
class PurchaseCreateView(CreateAPIView):
    queryset = Purchase.objects.all()
    serializer_class = PurchaseSerializer

class PurchaseDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Purchase.objects.all()
    serializer_class = PurchaseSerializer
    
class BookCreateView(CreateAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer

class BookDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    

class TodoListView(
  APIView, # Basic View class provided by the Django Rest Framework
  UpdateModelMixin, # Mixin that allows the basic APIView to handle PUT HTTP requests
  DestroyModelMixin, # Mixin that allows the basic APIView to handle DELETE HTTP requests
):

  def get(self, request, id=None):
    if id:
      # If an id is provided in the GET request, retrieve the User item by that id
      try:
        # Check if the User item the user wants to update exists
        queryset = User.objects.get(id=id)
      except User.DoesNotExist:
        # If the User item does not exist, return an error response
        return Response({'errors': 'This User item does not exist.'}, status=400)

      # Serialize User item from Django queryset object to JSON formatted data
      read_serializer = TodoSerializer(queryset)

    else:
      # Get all User items from the database using Django's model ORM
      queryset = User.objects.all()

      # Serialize list of todos item from Django queryset object to JSON formatted data
      read_serializer = TodoSerializer(queryset, many=True)

    # Return a HTTP response object with the list of User items as JSON
    return Response(read_serializer.data)


  def post(self, request):
    # Pass JSON data from user POST request to serializer for validation
    create_serializer = TodoSerializer(data=request.data)

    # Check if user POST data passes validation checks from serializer
    if create_serializer.is_valid():

      # If user data is valid, create a new User item record in the database
      todo_item_object = create_serializer.save()

      # Serialize the new User item from a Python object to JSON format
      read_serializer = TodoSerializer(todo_item_object)

      # Return a HTTP response with the newly created User item data
      return Response(read_serializer.data, status=201)

    # If the users POST data is not valid, return a 400 response with an error message
    return Response(create_serializer.errors, status=400)


  def put(self, request, id=None):
    try:
      # Check if the User item the user wants to update exists
      todo_item = User.objects.get(id=id)
    except User.DoesNotExist:
      # If the User item does not exist, return an error response
      return Response({'errors': 'This User item does not exist.'}, status=400)

    # If the User item does exists, use the serializer to validate the updated data
    update_serializer = TodoSerializer(todo_item, data=request.data)

    # If the data to update the User item is valid, proceed to saving data to the database
    if update_serializer.is_valid():

      # Data was valid, update the User item in the database
      todo_item_object = update_serializer.save()

      # Serialize the User item from Python object to JSON format
      read_serializer = TodoSerializer(todo_item_object)

      # Return a HTTP response with the newly updated User item
      return Response(read_serializer.data, status=200)

    # If the update data is not valid, return an error response
    return Response(update_serializer.errors, status=400)


  def delete(self, request, id=None):
    try:
      # Check if the User item the user wants to update exists
      todo_item = User.objects.get(id=id)
    except User.DoesNotExist:
      # If the User item does not exist, return an error response
      return Response({'errors': 'This User item does not exist.'}, status=400)

    # Delete the chosen User item from the database
    todo_item.delete()

    # Return a HTTP response notifying that the User item was successfully deleted
    return Response(status=204)
    