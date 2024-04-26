from django.db import models
from django.db.models.fields import AutoField
from django.db.models.fields import checks
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, AbstractUser
from django.contrib.auth.models import User

'''
class User(AbstractUser):
    class Meta:
      permissions = (('can_drive', 'Can drive'),)
  
class TodoManager(BaseUserManager):
    def create_user(self, email, username, password=None):
        if not email:
            raise ValueError('Users must have an email address')
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None):
        user = self.create_user(
            email,
            password=password,
            username=username,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class Todo(AbstractBaseUser):
    username = models.CharField( max_length=110, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False) # Tambahkan ini untuk kontrol admin
    is_staff = models.BooleanField(default=False) # Tambahkan ini untuk memenuhi kebutuhan Django admin
    is_superuser = models.BooleanField(default=False) # Tambahkan ini untuk superuser

    objects = TodoManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
  
    class Meta:
        db_table = 'todo'

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
'''


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE,
    related_name='user_profile')
    phone_number = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)

    def __str__(self):
        return self.user.username
    class Meta:
        db_table = 'user_profile'  # Nama tabel di database
        ordering = ['phone_number']  # Urutan default saat query
        verbose_name = 'user_profile'  # Nama yang lebih ramah untuk ditampilkan
        verbose_name_plural = 'user_profile'  
        
        
class Author(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField( max_length=105)
    birthdate = models.DateField()

    def __str__(self):
        return self.name
    class Meta:
        db_table = 'author'  # Nama tabel di database
        ordering = ['name']  # Urutan default saat query
        verbose_name = 'Author'  # Nama yang lebih ramah untuk ditampilkan
        verbose_name_plural = 'Authors'  # Bentuk jamak dari nama model
# Model untuk Tabel Kedua
class Publisher(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)

    def __str__(self):
        return self.name
        
    class Meta:
        db_table = 'publisher'
        ordering = ['name']
        verbose_name = 'Publisher'
        verbose_name_plural = 'Publishers'
# Model untuk Tabel Ketiga
class Book(models.Model):
    id = models.AutoField(primary_key= True)
    title = models.CharField(max_length=100)
    author = models.ForeignKey(Author, on_delete=models.CASCADE)
    publisher = models.ForeignKey(Publisher, on_delete=models.CASCADE)
    publication_date = models.DateField()

    def __str__(self):
        return self.title
    
    class Meta:
        db_table = 'book'
        ordering = ['-publication_date', 'title']  # Contoh pengurutan berdasarkan beberapa field
        verbose_name = 'Book'
        verbose_name_plural = 'Books'
        
# Model untuk Tabel Keempat
class Store(models.Model):
    id = models.AutoField(primary_key= True)
    name = models.CharField(max_length=110)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    books = models.ManyToManyField(Book,related_name='booklist_lu_groups')

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'store'
        ordering = ['name']
        verbose_name = 'Store'
        verbose_name_plural = 'Stores'
# Model untuk Tabel Kelima
class Customer(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField( max_length=110)
    purchased_books = models.ManyToManyField(Book,related_name='booklist_lu2_groups',  through='Purchase')

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'customer'
        ordering = ['name']
        verbose_name = 'Customer'
        verbose_name_plural = 'Customers'
# Model tambahan untuk mendefinisikan relasi antara Customer dan Book
class Purchase(models.Model):
    id = models.AutoField(primary_key=True)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    purchase_date = models.DateField()

    def __str__(self):
        return f"{self.customer.name} purchased {self.book.title}"
    
    class Meta:
        db_table = 'purchase'
        ordering = ['purchase_date']
        verbose_name = 'Purchase'
        verbose_name_plural = 'Purchases'     
       
    