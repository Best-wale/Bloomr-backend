from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from django.utils import timezone
from .models import LoginLog
from .serializers import LoginLogSerializer
from .models import Project
from .serializers import ProjectSerializer
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import CustomUser
#FarmerProfile, InvestorProfile
from .serializers import (
    CustomUserSerializer, RegisterSerializer,
    #FarmerProfileSerializer, InvestorProfileSerializer
)
from .serializers import ProjectUpdateCreateSerializer, KYCUploadSerializer
from django.shortcuts import get_object_or_404
from rest_framework.parsers import MultiPartParser, FormParser
import secrets

from rest_framework import generics
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Project
from .serializers import ProjectSerializer

class ProjectListCreateView(generics.ListCreateAPIView):
    authentication_classes = [TokenAuthentication]
    serializer_class = ProjectSerializer

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated()]
        return [AllowAny()]

    def get_queryset(self):
        user = getattr(self.request, 'user', None)
        mine = self.request.query_params.get('mine', 'false')
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')

        # Build the base queryset
        queryset = Project.objects.all()

        # Filter for authenticated user's own projects if requested
        if user and user.is_authenticated and (mine.lower() == '1' or mine.lower() == 'true'):
            queryset = queryset.filter(farmer=user)
        else:
            # Filter for public projects for non-authenticated users
            queryset = queryset.filter(is_public=True)

        # Apply date filtering if provided
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__lte=end_date)

        return queryset

    def perform_create(self, serializer):
        user = self.request.user
        if not getattr(user, 'role', '') == 'farmer':
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied('Only farmers may create projects')
        serializer.save(farmer=user)

class ProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = [TokenAuthentication]
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # allow public read without auth if project.is_public
        obj = self.get_object()
        if obj.is_public:
            self.permission_classes = [AllowAny]
        return super().get(request, *args, **kwargs)





# -----------------------------
# CustomUser Registration
# -----------------------------
class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        # Use serializer to create user (which will set password via serializer.create)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        # Create auth token for the new user
        
        token, _ = Token.objects.get_or_create(user=user)
        data = CustomUserSerializer(user).data
        return Response({'token': token.key, 'user': data}, status=status.HTTP_201_CREATED)


# -----------------------------
# Current CustomUser
# -----------------------------
class MeView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = CustomUserSerializer(request.user)
        return Response(serializer.data)


class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email', '').strip().lower()
        password = request.data.get('password', '')
        ip = request.META.get('REMOTE_ADDR') or request.META.get('HTTP_X_FORWARDED_FOR')
        ua = request.META.get('HTTP_USER_AGENT', '')

        user = None
        success = False
        message = ''

        if not email or not password:
            message = 'Email and password are required.'
            LoginLog.objects.create(email=email, success=False, ip_address=ip, user_agent=ua, message=message)
            return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=email, password=password)
        if user is None:
            message = 'Invalid credentials.'
            LoginLog.objects.create(email=email, success=False, ip_address=ip, user_agent=ua, message=message)
            return Response({'error': message}, status=status.HTTP_401_UNAUTHORIZED)

        # At this point authentication succeeded
        success = True
        # create or get token
        token, created = Token.objects.get_or_create(user=user)

        LoginLog.objects.create(user=user, email=email, success=True, ip_address=ip, user_agent=ua, message='Login successful')
        print(CustomUserSerializer(user).data)
        return Response({'token': token.key, 'user': CustomUserSerializer(user).data})


# Endpoint: POST /bloomr/projects/<pk>/updates/  (create update for a project)
class ProjectUpdateCreateView(generics.CreateAPIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = ProjectUpdateCreateSerializer

    def perform_create(self, serializer):
        # Ensure author is the authenticated user and project exists
        user = self.request.user
        project = get_object_or_404(Project, pk=self.kwargs.get('pk'))
        # Only the farmer who owns the project may post updates
        if project.farmer != user:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied('Only the project owner may post updates')
        serializer.save(author=user, project=project)


# Endpoint: POST /bloomr/kyc/  (file upload)
class KYCUploadCreateView(generics.CreateAPIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = KYCUploadSerializer
    parser_classes = [MultiPartParser, FormParser]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class WalletConnectView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        wallet = request.data.get('wallet_address')
        if not wallet:
            return Response({'detail': 'wallet_address required'}, status=status.HTTP_400_BAD_REQUEST)
        user = request.user
        user.wallet_address = wallet
        user.save()
        return Response({'detail': 'wallet saved', 'wallet_address': wallet})


class WalletNonceView(APIView):
    """GET: create a nonce for the authenticated user.
       POST: optionally accept wallet_address to create nonce for different address.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        nonce = secrets.token_hex(16)
        from .models import WalletNonce
        wn = WalletNonce.objects.create(user=user, nonce=nonce)
        return Response({'nonce': nonce, 'id': wn.id})


class WalletVerifyView(APIView):
    """Accepts { wallet_address, nonce, signature } and verifies ownership.
       NOTE: This is a placeholder that marks verification as successful; for production
       you must verify the signature using Hedera SDK or HashConnect client signed payloads.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        wallet = request.data.get('wallet_address')
        nonce = request.data.get('nonce')
        signature = request.data.get('signature')
        public_key = request.data.get('public_key')
        if not wallet or not nonce or not signature or not public_key:
            return Response({'detail': 'wallet_address, nonce, signature and public_key required'}, status=status.HTTP_400_BAD_REQUEST)

        from .models import WalletNonce
        try:
            wn = WalletNonce.objects.get(nonce=nonce, user=request.user, used=False)
        except WalletNonce.DoesNotExist:
            return Response({'detail': 'Invalid or used nonce'}, status=status.HTTP_400_BAD_REQUEST)

        # Verify signature using Hedera SDK (ed25519)
        try:
            from hedera import Ed25519PublicKey
            import base64, binascii

            # public_key may be provided in several formats - try common ones
            pub = None
            try:
                # try direct string (e.g., '302a...') as hex
                pub = Ed25519PublicKey.fromString(public_key)
            except Exception:
                try:
                    # if base64
                    decoded = base64.b64decode(public_key)
                    pub = Ed25519PublicKey.fromBytes(decoded)
                except Exception:
                    try:
                        # if hex
                        decoded = binascii.unhexlify(public_key)
                        pub = Ed25519PublicKey.fromBytes(decoded)
                    except Exception:
                        pub = None

            if pub is None:
                return Response({'detail': 'Unable to parse public_key'}, status=status.HTTP_400_BAD_REQUEST)

            # signature may be base64 or hex
            sig_bytes = None
            try:
                sig_bytes = base64.b64decode(signature)
            except Exception:
                try:
                    sig_bytes = binascii.unhexlify(signature)
                except Exception:
                    sig_bytes = None

            if sig_bytes is None:
                return Response({'detail': 'Unable to parse signature'}, status=status.HTTP_400_BAD_REQUEST)

            # nonce was created as hex string; verify signature over nonce bytes
            try:
                nonce_bytes = nonce.encode('utf-8')
            except Exception:
                nonce_bytes = nonce

            # Ed25519PublicKey in hedera SDK has a verify method
            try:
                pub.verify(nonce_bytes, sig_bytes)
            except Exception as e:
                return Response({'detail': 'Signature verification failed', 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'detail': 'Verification error', 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # If verification passed, mark nonce used and bind wallet
        wn.used = True
        wn.save()
        user = request.user
        user.wallet_address = wallet
        # also optionally store public_key for later use
        try:
            user.wallet_public_key = public_key
        except Exception:
            pass
        user.save()
        return Response({'detail': 'wallet verified and bound', 'wallet_address': wallet})


# -----------------------------
# Farmer Profile (view/update)
# -----------------------------
'''
class FarmerProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = FarmerProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Ensure the CustomUser is a farmer
        if self.request.CustomUser.role != 'farmer':
            raise PermissionError("Only farmers can access this.")
        return self.request.CustomUser.farmer_profile


# -----------------------------
# Investor Profile (view/update)
# -----------------------------
class InvestorProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = InvestorProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Ensure the CustomUser is an investor
        if self.request.CustomUser.role != 'investor':
            raise PermissionError("Only investors can access this.")
        return self.request.CustomUser.investor_profile
'''