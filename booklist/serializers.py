from rest_framework import serializers
from .models import  Author, Publisher, Customer, Purchase, Store, Book
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from .models import UserProfile
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, BlacklistedToken
import re

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['username'] = user.username
        token['email'] = user.email
        
        return token
        
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('phone_number', 'address')

    def create(self, validated_data):

        return UserProfile.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.address = validated_data.get('address', instance.address)
        instance.save()
        return instance
        
class UpdatePassSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def validate_old_password(self, value):
        # Ambil user_id dari context
        user_id = self.context.get('user_id')
        print(user_id)
        user = User.objects.get(id=user_id)
        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):
        # Hapus 'old_password' dan 'password2' dari validated_data
        validated_data.pop('old_password', None)
        validated_data.pop('password2', None)

        # Perbarui password
        instance.password = make_password(validated_data.get('password'))
        instance.save()

        return instance
"""class UpdateUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True,
    validators=[validate_password])
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    phone_number = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'first_name', 'last_name',
        'phone_number')

    def validate(self, attrs):
        if not attrs['password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def validate_password(self, value):
        # Ambil user_id dari context
        user_id = self.context.get('user_id')
        print(user_id)
        user = User.objects.get(id=user_id)
        if not user.check_password(value):
            raise serializers.ValidationError({"password": "password is not correct"})
        return value

    def update(self, instance, validated_data):
        
        instance.username = validated_data.get("username")
        instance.first_name = validated_data.get("first_name")
        instance.last_name = validated_data.get("last_name")
        instance.phone_number = validated_data.get("phone_number")
        instance.save()

        return instance"""
        

class UserSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer()

    class Meta:
        model = User
        fields = ('username', 'password', 'email', 'first_name', 'last_name', 'user_profile')
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'password': {'write_only': True}
        }

    def validate_username(self, value):
        if not re.match(r'^[\w\s]+$', value):
            raise serializers.ValidationError("Username hanya boleh mengandung huruf, angka, spasi, dan underscore.")
        return value

    def create(self, validated_data):
        profile_data = validated_data.pop('user_profile')
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_staff=1
        )
        user.set_password(validated_data['password'])
        user.save()

        UserProfile.objects.create(
            user=user,
            phone_number=profile_data['phone_number'],
            address=profile_data['address']
        )

        return user

        
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    phone_number= serializers.CharField(required=False)
    password = serializers.CharField()
    def validate(self, data):
        username = data.get("username")
        email = data.get("email")
        phone_number = data.get("phone_number")
        password = data.get("password")
        print(email, password)
        if username and password:
          user = authenticate(username = username, password = password)
          print(user)
         
          if user:
              tokens = RefreshToken.for_user(user)
              return {
                        'refresh': str(tokens),
                        'access': str(tokens.access_token)
                }
          raise serializers.ValidationError("Invalid credentials")
        if email and password:
          user = User.objects.filter(email=email).first()
          #tokens = RefreshToken.for_user(user)
          if not user.check_password(password):
              raise serializers.ValidationError("Incorrect credentials")
          if user and user.check_password(password):
                tokens = RefreshToken.for_user(user)
                return {
                        'refresh': str(tokens),
                        'access': str(tokens.access_token)
                }
          raise serializers.ValidationError("Invalid credentials")
        if phone_number and password:
          user = UserProfile.objects.filter(phone_number=phone_number).first()
          #tokens = RefreshToken.for_user(user)
          account = User.objects.get(id=user.id)
          if not account.check_password(password):
              raise serializers.ValidationError("Incorrect credentials")
          if user:
                user_data = user.user
                if user_data.check_password(password):
                    tokens = RefreshToken.for_user(user_data)
                    return {
                        'refresh': str(tokens),
                        'access': str(tokens.access_token)
                }
          raise serializers.ValidationError("Invalid credentials")
        
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            # Blacklist the provided refresh token
            token = RefreshToken(self.token)
            token.blacklist()

            # Try to remove the refresh token from outstanding tokens
            try:
                outstanding_token = OutstandingToken.objects.get(token=self.token)
                outstanding_token.delete()
            except OutstandingToken.DoesNotExist:
                pass

            # Note: Access tokens cannot be forcibly 'revoked' if they are already issued,
            # but they will be automatically invalidated once the refresh token is blacklisted
            # and the access token expires.

            return 'Token invalidated successfully'
        except:
          return 'bad_token'
            
class UpdateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email')
        extra_kwargs = {
            'username': {'required': True},
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate_email(self, value):
        if User.objects.exclude(pk=self.instance.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_username(self, value):
        if User.objects.exclude(pk=self.instance.pk).filter(username=value).exists():
            raise serializers.ValidationError("This username is already in use.")
        return value

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.save()
        return instance

class UserProfileSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(required=True)
    address = serializers.CharField(required=True)

    class Meta:
        model = UserProfile
        fields = ('phone_number','address')

    def update(self, instance, validated_data):
        instance.phone_number = validated_data.get('phone_number')
        instance.phone_number = validated_data.get('addres')
        instance.save()
        return instance

class TodoSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  
        extra_kwargs = {'password': {'write_only': True}}


class AuthorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Author
        fields = '__all__'  

class PublisherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Publisher
        fields = '__all__'  

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'  

class PurchaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Purchase
        fields = '__all__'  
class StoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = Store
        fields = '__all__'  

class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = '__all__'  

