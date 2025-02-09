from django.core.mail import EmailMessage
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from gfg import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import generate_token
from django.contrib.auth.forms import PasswordResetForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required

# Home view
def home(request):
    
    return render(request, "authentication/index.html")


@login_required
def dashboard(request):
    # Get the logged-in user
    user = request.user  # This will give the logged-in user's info
    
    # Pass user info to the template
    return render(request, "authentication/index.html", {
        'fname': user.first_name,
        'lname': user.last_name,
        'email': user.email,
    })

# Signup view
def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists! Please try another username")
            return redirect('home')
        
        if User.objects.filter(email=email):
            messages.error(request, "Email already exists")
            return redirect('home')
        
        if len(username) > 10:
            messages.error(request, "Username must be under 10 characters")
            return redirect('home')

        if pass1 != pass2:
            messages.error(request, "Passwords didn't match!")
            return redirect('home')

        if not username.isalnum():
            messages.error(request, "Username must be alphanumeric!")
            return redirect('home')

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        messages.success(request, "Your account has been successfully created. We have sent you a confirmation mail. Please confirm this to activate your account.")

        # Send welcome email
        subject = "Welcome to GFG"
        message = f"Hello {myuser.first_name} || \nWelcome to GFG!! \nThank you for visiting our website. \nWe have also sent you a confirmation email. Please confirm your email address to activate your account.\n\nThanking You\nVaibhav Gupta"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Send confirmation email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email - Django login"
        message2 = render_to_string("email_confirmation.html", {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently = True
        email.send()

        return redirect('signin')

    return render(request, "authentication/signup.html")

# Signin view
def signin(request):
    if request.method == "POST":
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            lname = user.last_name  # Get last name
            email = user.email  # Get email
            return render(request, "authentication/dashboard.html", {'fname': fname, 'lname': lname, 'email': email})
        else:
            messages.error(request, "Bad Credentials!")
            return redirect('home')

    return render(request, "authentication/signin.html")

# Signout view
def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect('home')

# Account activation view
def activate(request, uid64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
    
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        
        # Pass first name, last name, and email to the template
        fname = myuser.first_name
        lname = myuser.last_name
        email = myuser.email
        return render(request, 'authentication/index.html', {'fname': fname, 'lname': lname, 'email': email})
    else:
        return render(request, 'activation_failed.html')

# Forgot password form view
def forgot_password(request):
    if request.method == "POST":
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            current_site = get_current_site(request)
            email_subject = "Password Reset Request"
            message = render_to_string('authentication/password_reset_email.html', {
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
                'user': user  # Pass the user object to access first_name
            })

            email = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [user.email],
            )
            email.fail_silently = False
            email.send()

            messages.success(request, "Password reset link sent! Please check your email.")
            return redirect('home')
        else:
            messages.error(request, "No user found with this email address.")
            return redirect('forgot_password')

    return render(request, "authentication/forgot_password.html")

# Reset password view
def reset_password(request, uid64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == "POST":
            new_password = request.POST['new_password']
            confirm_password = request.POST['confirm_password']
            
            if new_password != confirm_password:
                messages.error(request, "Passwords don't match!")
                return redirect(f'reset_password/{uid64}/{token}/')

            user.set_password(new_password)
            user.save()
            messages.success(request, "Password has been reset successfully!")
            return redirect('signin')
        
        return render(request, 'authentication/reset_password.html', {'uid64': uid64, 'token': token})
    else:
        messages.error(request, "Invalid or expired reset link.")
        return redirect('home')

# Change password view (Requires authentication)
@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        
        if form.is_valid():
            # Save the new password
            form.save()

            # Update the session to keep the user logged in after password change
            update_session_auth_hash(request, form.user)

            messages.success(request, "Your password has been successfully updated!")
            return redirect('signin')  # Redirect to your dashboard or home page
        else:
            messages.error(request, "Please correct the errors below.")

    else:
        form = PasswordChangeForm(user=request.user)

    return render(request, 'authentication/change_password.html', {'form': form})

@login_required
def profile(request):
    return render(request, 'authentication/profile.html')

