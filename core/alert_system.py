import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()  # Load from .env file

def send_alert(filename, detections):
    msg = MIMEText(f"""
    Suspicious file detected!
    Name: {filename}
    Reasons: {', '.join(detections)}
    """)
    msg['Subject'] = "🚨 MALWARE ALERT"
    msg['From'] = os.getenv("ALERT_EMAIL")
    msg['To'] = os.getenv("USER_EMAIL")

    with smtplib.SMTP(os.getenv("SMTP_SERVER"), 587) as server:
        server.starttls()
        server.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
        server.send_message(msg)
