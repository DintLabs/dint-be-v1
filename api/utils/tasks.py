# from django.conf import settings
# from django.core.mail import EmailMessage
# from django.template.loader import render_to_string

# DEFAULT_FROM_EMAIL = settings.DEFAULT_FROM_EMAIL

# def send_email(subject, template, to_email, from_email=DEFAULT_FROM_EMAIL):
    
#     html_content =""

#     msg = EmailMessage(subject=subject, html_content, to=[to_email], from_email=from_email)
#     msg.content_subtype = "html"

#     msg.send()