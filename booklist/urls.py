from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from .views import (TodoCreateView, TodoDetailView, AuthorCreateView,
AuthorDetailView, PublisherCreateView, PublisherDetailView, CustomerCreateView,
CustomerDetailView, TodoListView, StoreDetailView, StoreCreateView,
PurchaseDetailView, PurchaseCreateView, BookCreateView, BookDetailView,
LoginView, RegisterView, LoginAPIView, RestrictedView,
UpdateProfileView,LogoutAPIView, UpdatePassView, MyTokenObtainPairView)

urlpatterns = [
    path('todos/', TodoCreateView.as_view(), name='todo-list'),
    path('todos/<int:pk>/', TodoDetailView.as_view(), name='todo-detail'),
    path('todos/all/', TodoListView.as_view(), name='todo-all-detail'),
    path('authors/', AuthorCreateView.as_view(), name='author-list'),
    path('authors/<int:pk>/', AuthorDetailView.as_view(), name='author-detail'),
    path('publishers/', PublisherCreateView.as_view(), name='publisher-list'),
    path('publishers/<int:pk>/', PublisherDetailView.as_view(), name='publisher-detail'),
    path('customers/', CustomerCreateView.as_view(), name='customer-list'),
    path('customers/<int:pk>/', CustomerDetailView.as_view(), name='customer-detail'),
    path('store/', StoreCreateView.as_view(), name='customer-list'),
    path('store/<int:pk>/', StoreDetailView.as_view(), name='customer-detail'),
    path('purchase/', PurchaseCreateView.as_view(), name='customer-list'),
    path('purchase/<int:pk>/', PurchaseDetailView.as_view(), name='customer-detail'),
    path('book/', BookCreateView.as_view(), name='customer-list'),
    path('book/<int:pk>/', BookDetailView.as_view(), name='customer-detail'),
    
    path('api/login/', LoginView.as_view(), name='api_login'),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/update/password/<int:pk>/', UpdatePassView.as_view(), name='update-pass'),
    path('api/update/profile/<int:pk>/', UpdateProfileView.as_view(), name='auth_update_profile'),
    #path('login/', LoginView.as_view(), name='login'),
    path('api/restricted/', RestrictedView.as_view(), name='access'),
    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name ='token_obtain_pair'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(),
    name='token_refresh'),
    path('api/logout/', LogoutAPIView.as_view(), name="logout"),
    path('token/', MyTokenObtainPairView.as_view(), name="custom token")
]
