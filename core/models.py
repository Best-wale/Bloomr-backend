from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.models import User
from django.conf import settings
from django.utils import timezone
 


# ---------------------------------------------------------------------
# 1. Custom User
# ---------------------------------------------------------------------





class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('investor', 'Investor'),
        ('farmer', 'Farmer'),
        
    ]
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='investor',
        help_text="Determines user capabilities in the system.")
    wallet_address = models.CharField(max_length=200, blank=True, null=True, help_text='Optional Hedera account id or wallet address')
    wallet_public_key = models.TextField(blank=True, null=True, help_text='Optional Hedera public key (saved after verification)')

    USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS should list the names of required fields (strings),
    # not the field objects. Include fields that should be prompted when
    # creating a superuser (email is the USERNAME_FIELD so exclude it).
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

'''
class User(AbstractUser):
    """
    Main user model for all roles.
    """
    ROLE_CHOICES = [
        ('investor', 'Investor'),
        ('farmer', 'Farmer'),
        ('admin', 'Admin'),
    ]
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='investor',
        help_text="Determines user capabilities in the system."
    )
    wallet_address = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Optional Web3 wallet for payouts or investments."
    )
    # Signup form fields
    newsletter_opt_in = models.BooleanField(
        default=True,
        help_text="Whether the user opted in to marketing/newsletter emails."
    )
    terms_accepted = models.BooleanField(
        default=False,
        help_text="Whether the user accepted terms and privacy policy at signup."
    )

    def __str__(self):
        return f"{self.username} ({self.role})"
'''

# ---------------------------------------------------------------------
# 2. Farmer Profile
# ---------------------------------------------------------------------
'''
class FarmerProfile(models.Model):
    """
    Extra details for farmer users only.
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="farmer_profile",
        limit_choices_to={'role': 'farmer'}
    )
    farm_name = models.CharField(max_length=150, blank=True)
    farm_location = models.CharField(max_length=255, blank=True)
    farm_size_hectares = models.DecimalField(
        max_digits=6, decimal_places=2,
        help_text="Approx. size of farm in hectares"
    )
    description = models.TextField(blank=True)
    id_document = models.ImageField(
        upload_to="farmer_ids/",
        blank=True,
        null=True,
        help_text="National ID or certificate for verification"
    )
    is_verified = models.BooleanField(default=False)
    date_submitted = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"FarmerProfile: {self.farm_name} ({self.user.username})"


# ---------------------------------------------------------------------
# 3. Investor Profile
# ---------------------------------------------------------------------
class InvestorProfile(models.Model):
    """
    Extra details for investor users only.
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="investor_profile",
        limit_choices_to={'role': 'investor'}
    )
    full_name = models.CharField(max_length=150, blank=True)
    contact_number = models.CharField(max_length=50, blank=True)
    preferred_sectors = models.CharField(
        max_length=255,
        blank=True,
        help_text="Optional comma-separated list of sectors/crops of interest."
    )
    # Map the signup's "investment interest" select to this field
    investment_interest = models.CharField(
        max_length=100,
        blank=True,
        help_text="Primary investment interest selected during signup."
    )
    kyc_document = models.FileField(
        upload_to="investor_kyc/",
        blank=True,
        null=True,
        help_text="Upload government ID or KYC proof."
    )
    is_verified = models.BooleanField(default=False)
    date_submitted = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"InvestorProfile: {self.full_name} ({self.user.username})"


# ---------------------------------------------------------------------
# 4. Optional Farm Project (if farmers list projects for investment)
# ---------------------------------------------------------------------
class FarmProject(models.Model):
    farmer = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'farmer'},
        related_name='projects'
    )
    title = models.CharField(max_length=150)
    description = models.TextField()
    funding_goal = models.DecimalField(max_digits=12, decimal_places=2)
    funds_raised = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    is_open = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.title} ({self.farmer.username})"
'''


# ---------------------------------------------------------------------
# 5. Login Audit Log
# ---------------------------------------------------------------------
class LoginLog(models.Model):
    user = models.ForeignKey(CustomUser, null=True, blank=True, on_delete=models.SET_NULL, related_name='login_logs')
    email = models.CharField(max_length=255, blank=True)
    success = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    message = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"LoginLog(email={self.email} success={self.success} at={self.created_at})"


# ---------------------------------------------------------------------
# 6. Farm Project (detailed)
# ---------------------------------------------------------------------
class Project(models.Model):
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('fundraising', 'Fundraising'),
        ('growing', 'Growing'),
        ('harvest', 'Harvest Phase'),
        ('completed', 'Completed'),
        ('closed', 'Closed')
    ]

    farmer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='projects', limit_choices_to={'role': 'farmer'})
    title = models.CharField(max_length=150)
    short_description = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    funding_goal = models.DecimalField(max_digits=12, decimal_places=2)
    funds_raised = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    investors_count = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    image = models.ImageField(upload_to='farm_image')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_public = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.farmer.email})"

    @property
    def percent_funded(self):
        try:
            if not self.funding_goal or self.funding_goal == 0:
                return 0
            return min(100, int((self.funds_raised / self.funding_goal) * 100))
        except Exception:
            return 0


# ---------------------------------------------------------------------
# 7. Project Updates
# ---------------------------------------------------------------------
class ProjectUpdate(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='updates')
    author = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='project_updates')
    content = models.TextField(blank=True)
    image = models.CharField(max_length=255, blank=True, help_text='Optional image or emoji id')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Update for {self.project.title} by {self.author.email} at {self.created_at}"


# ---------------------------------------------------------------------
# 8. KYC Uploads
# ---------------------------------------------------------------------
class KYCUpload(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='kyc_uploads')
    document = models.FileField(upload_to='kyc_documents/')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"KYC {self.user.email} - {self.status}"


# ---------------------------------------------------------------------
# 9. Wallet Nonce for verification
# ---------------------------------------------------------------------
class WalletNonce(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='wallet_nonces')
    nonce = models.CharField(max_length=128)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Nonce for {self.user.email} at {self.created_at} (used={self.used})"

