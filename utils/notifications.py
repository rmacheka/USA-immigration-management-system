# utils/notifications.py - Notification utility functions
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from app.config import settings
import logging

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Email notification service"""
    
    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
    
    def send_email(
        self, to_email: str, subject: str, body_text: str, body_html: Optional[str] = None
    ) -> bool:
        """Send an email"""
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = to_email
            
            # Add text part
            part1 = MIMEText(body_text, "plain")
            msg.attach(part1)
            
            # Add HTML part if provided
            if body_html:
                part2 = MIMEText(body_html, "html")
                msg.attach(part2)
            
            # Connect to server and send
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.from_email, to_email, msg.as_string())
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    def send_permit_expiry_notification(self, to_email: str, permit_number: str, expiry_date: date, days_remaining: int) -> bool:
        """Send permit expiration notification"""
        subject = f"Immigration Permit {permit_number} Expires in {days_remaining} Days"
        
        body_text = f"""
        Dear Permit Holder,
        
        Your immigration permit (Permit Number: {permit_number}) will expire on {expiry_date}.
        You have {days_remaining} days remaining before expiration.
        
        Please log in to your account to review your options for renewal or extension.
        
        Regards,
        USA Immigration System
        """
        
        body_html = f"""
        <html>
        <body>
            <h2>Immigration Permit Expiration Notice</h2>
            <p>Dear Permit Holder,</p>
            <p>Your immigration permit (Permit Number: <strong>{permit_number}</strong>) will expire on <strong>{expiry_date}</strong>.</p>
            <p>You have <strong>{days_remaining} days</strong> remaining before expiration.</p>
            <p>Please <a href="{settings.APPLICATION_URL}/login">log in to your account</a> to review your options for renewal or extension.</p>
            <p>Regards,<br>USA Immigration System</p>
        </body>
        </html>
        """
        
        return self.send_email(to_email, subject, body_text, body_html)

