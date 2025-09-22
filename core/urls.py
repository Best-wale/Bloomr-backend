from django.urls import path
from .views import RegisterView, MeView, LoginAPIView
from .views import ProjectListCreateView, ProjectDetailView
from .views import ProjectUpdateCreateView, KYCUploadCreateView
from .views import WalletConnectView
from .views import WalletNonceView, WalletVerifyView
#FarmerProfileView, InvestorProfileView

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginAPIView.as_view(), name='login'),  # custom token login with logging
    path('auth/me/', MeView.as_view(), name='me'),
    path('projects/', ProjectListCreateView.as_view(), name='projects'),
    path('projects/<int:pk>/', ProjectDetailView.as_view(), name='project-detail'),
    path('projects/<int:pk>/updates/', ProjectUpdateCreateView.as_view(), name='project-updates'),
    path('kyc/', KYCUploadCreateView.as_view(), name='kyc-upload'),
    path('wallet/connect/', WalletConnectView.as_view(), name='wallet-connect'),
    path('wallet/nonce/', WalletNonceView.as_view(), name='wallet-nonce'),
    path('wallet/verify/', WalletVerifyView.as_view(), name='wallet-verify'),
]
#    path('farmer/profile/', FarmerProfileView.as_view(), name='farmer_profile'),
#   path('investor/profile/', InvestorProfileView.as_view(), name='investor_profile'),

