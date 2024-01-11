from django.urls import path
from .views import RegisterUserView, VerifyUserEmail

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify_email/', VerifyUserEmail.as_view(), name='verify')
]
