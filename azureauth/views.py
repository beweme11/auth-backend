from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
import requests
from django.views.decorators.csrf import csrf_exempt
import json
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer
from django.db import IntegrityError
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

@csrf_exempt
@api_view(['POST'])
def SSOuserRegistration(request):
    if request.method == 'POST':
        body_data = json.loads(request.body.decode('utf-8'))
        msft_token = body_data.get('accessToken')
        url = 'https://graph.microsoft.com/oidc/userinfo'
        
        headers = {
            "Authorization": f"Bearer {msft_token}",
            "Content-Type": "application/json"
        }
        
        if not msft_token:
            return Response({"error": "Access token required"})
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                user_data = response.json()
                name = f"{user_data.get('givenname')} {user_data.get('familyname')}"
                email = user_data.get('email')
                
                try:
                    sso_user = User.objects.create_user(email=email, name=name, sso=True)
                    print("Registration success")

                    refresh = RefreshToken.for_user(sso_user)
                    access = str(refresh.access_token)
                    
                    return Response({'message': 'success', 'access_token': access, 'refresh_token': str(refresh)})
                    
                except IntegrityError:
                    sso_user = User.objects.get(email=email)
                    sso_user.name = name
                    sso_user.sso = True
                    sso_user.save()
                    print("User updated")

                    refresh = RefreshToken.for_user(sso_user)
                    access = str(refresh.access_token)

                    return Response({'message': 'success', 'access_token': access, 'refresh_token': str(refresh)})
                
            else:
                return Response({"error": f"Failed to get user data: {response.text}"}, status=response.status_code)
        except Exception as e:
            print(str(e))
            return Response({'error': str(e)})
    else:
        return Response({'error': 'Method not allowed'})

@csrf_exempt
@api_view(['POST'])
def Signup(request):
    if request.method == 'POST':
        body_data = json.loads(request.body.decode('utf-8'))
        name = body_data.get('name')
        email = body_data.get('email')
        password = body_data.get('password')
        
        if not email or not password:
            return Response({"error": "Email and password are required"})
        try:
            user = User.objects.create_user(email=email, name=name, password=password)
            print("USERRR : {user}")

            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            return Response({'message': 'User created', 'access_token': access, 'refresh_token': str(refresh)})

        except Exception as e:
            print(str(e))
            return Response({'error': str(e)})
    else:
        return Response({'error': 'Method not allowed'})

@csrf_exempt
@api_view(['POST'])
def signin(request):
    if request.method == 'POST':
        body_data = json.loads(request.body.decode('utf-8'))
        
        email = body_data.get('email')
        password = body_data.get('password')
        user = User.objects.filter(email=email).first()
        
        if user is None:
            raise AuthenticationFailed('User not found!')
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')
        
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

        return Response({'message': 'User updated', 'access_token': access, 'refresh_token': str(refresh)})
    else:
        return Response({'message': 'Method not allowed'})

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])

def getUsersdata(request):
    if request.method == 'GET':
        users = User.objects.all()  
        serializer = UserSerializer(users, many=True) 
        return Response(serializer.data)
    else:
        return Response({'message': 'Method not allowed'})
