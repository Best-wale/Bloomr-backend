from rest_framework import serializers
from .models import CustomUser
#FarmerProfile, InvestorProfile
from .models import LoginLog
from .models import Project,ProjectUpdate,KYCUpload

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        # include wallet_public_key so frontend can display or use it
        fields = '__all__'

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email','first_name', 'last_name','role','password']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        # Create user using manager to ensure password hashing
        user = CustomUser.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

    
'''

class FarmerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = FarmerProfile
        fields = [
            'id', 'farm_name', 'farm_location', 'farm_size_hectares',
            'description', 'id_document', 'is_verified', 'date_submitted'
        ]
        read_only_fields = ['is_verified', 'date_submitted']


class InvestorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvestorProfile
        fields = [
            'id', 'full_name', 'contact_number',
            'preferred_sectors', 'kyc_document',
            'is_verified', 'date_submitted'
        ]
        read_only_fields = ['is_verified', 'date_submitted']
'''


class LoginLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginLog
        fields = ['id', 'user', 'email', 'success', 'ip_address', 'user_agent', 'message', 'created_at']
        read_only_fields = ['id', 'created_at']


from rest_framework import serializers
from .models import Project

class ProjectSerializer(serializers.ModelSerializer):
    percent_funded = serializers.IntegerField(read_only=True)
    farmer_email = serializers.CharField(source='farmer.email', read_only=True)

    class Meta:
        model = Project
        fields = ['id', 'title', 'short_description', 'description', 'location', 'funding_goal', 
                  'funds_raised', 'investors_count', 'status', 'image', 'is_public', 
                  'created_at', 'updated_at', 'percent_funded', 'farmer', 'farmer_email']
        read_only_fields = ['id', 'created_at', 'updated_at', 'percent_funded', 'farmer_email', 'farmer']

    def validate_image(self, value):
        # Set your validation criteria
        max_size = 5 * 1024 * 1024  # 5 MB
        allowed_formats = ['image/jpeg', 'image/png']

        # Check file size
        if value.size > max_size:
            raise serializers.ValidationError("Image file too large ( > 5MB )")

        # Check file format
        if value.content_type not in allowed_formats:
            raise serializers.ValidationError("Unsupported file type. Only JPEG and PNG are allowed.")

        return value

class ProjectUpdateSerializer(serializers.ModelSerializer):
    author_email = serializers.CharField(source='author.email', read_only=True)
    class Meta:
        model = Project
        fields = ['id']


class ProjectUpdateCreateSerializer(serializers.ModelSerializer):
    author_email = serializers.CharField(source='author.email', read_only=True)
    class Meta:
        model = ProjectUpdate
        fields = ['id', 'project', 'author', 'content', 'image', 'created_at']
        read_only_fields = ['id', 'author', 'created_at']


class KYCUploadSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    class Meta:
        model = KYCUpload
        fields = ['id', 'user', 'document', 'status', 'submitted_at', 'user_email']
        read_only_fields = ['id', 'status', 'submitted_at', 'user']