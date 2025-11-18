from django.db import models

# Create your models here.


class Menu(models.Model):
    DishId=models.IntegerField(primary_key=True)
    DishName=models.CharField(max_length=50)
    Ingredients=models.TextField()
    Category=models.CharField(max_length=20)
    Price=models.FloatField()
    # Image=models.FileField(upload_to="profile/")
    Image=models.URLField()


class Users(models.Model):
    Userid=models.IntegerField(primary_key=True)
    Username=models.CharField(max_length=50)
    Email=models.EmailField(max_length=50,null=False,unique=True)
    Password=models.CharField(max_length=225,null=False)
    Role=models.CharField(max_length=20, default='User')