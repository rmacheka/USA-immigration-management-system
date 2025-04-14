import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import pandas as pd
from datetime import datetime, timedelta
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("notifications")

class EmailNotifier:
    """Class to handle email notifications for the immigration system"""
    
    def __init__(self, smtp_server=None, smtp_port=None, username=None, password=None):
        """
        Initialize the email notifier
        
        Args:
            smtp_server (str): SMTP server address
            smtp_port (int): SMTP server port
            username (str): SMTP username
            password (str): SMTP password
        """
        # Load from environment variables if not provided
        self.smtp_server = smtp_server or os.environ.get("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = smtp_port or int(os.environ.get("SMTP_PORT", 587))
        self.username = username or os.environ.get("SMTP_USERNAME", "")
        self.password = password or os.environ.get("SMTP_PASSWORD", "")
        
        # Check if credentials are available
        self.credentials_available = bool(self.username and self.password)
        if not self.credentials_available:
            logger.warning("SMTP credentials not available. Email notifications will be simulated.")
    
    def send_email(self, recipient, subject, body, attachments=None, html=False):
        """
        Send an email
        
        Args:
            recipient (str): Email recipient
            subject (str): Email subject
            body (str): Email body
            attachments (list): List of file paths to attach
            html (bool): Whether the email body is HTML
        
        Returns:
            bool: Whether the email was sent successfully
        """
        if not self.credentials_available:
            logger.info(f"Simulating email to {recipient}: {subject}")
            logger.info(f"Email body: {body[:100]}...")
            return True
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # Add body
            if html:
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))
            
            # Add attachments
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as file:
                            part = MIMEApplication(file.read(), Name=os.path.basename(file_path))
                        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
                        msg.attach(part)
            
            # Connect to server and send
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {recipient}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def send_permit_expiry_notification(self, recipient, immigrant_data, days_threshold=30):
        """
        Send a notification about permits that will expire soon
        
        Args:
            recipient (str): Email recipient
            immigrant_data (DataFrame): DataFrame with immigrant records
            days_threshold (int): Days threshold for expiry warning
        
        Returns:
            bool: Whether the email was sent successfully
        """
        # Convert permit expiry to datetime
        df = immigrant_data.copy()
        df['Permit Expiry'] = pd.to_datetime(df['Permit Expiry'], errors='coerce')
        
        # Calculate days until expiry
        today = datetime.now().date()
        df['Days Until Expiry'] = (df['Permit Expiry'].dt.date - today).dt.days
        
        # Filter immigrants with permits expiring soon
        expiring_soon = df[(df['Days Until Expiry'] >= 0) & (df['Days Until Expiry'] <= days_threshold)]
        
        if len(expiring_soon) == 0:
            logger.info("No permits expiring soon. No notification sent.")
            return True
        
        # Create email body
        subject = f"Permit Expiry Alert: {len(expiring_soon)} permit(s) expiring soon"
        
        html_body = f"""
        <html>
        <head>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                }}
                th, td {{
                    border: 1px solid #dddddd;
                    text-align: left;
                    padding: 8px;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                tr:nth-child(even) {{
                    background-color: #f9f9f9;
                }}
                .urgent {{
                    color: red;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <h2>Permit Expiry Alert</h2>
            <p>The following {len(expiring_soon)} permit(s) will expire within the next {days_threshold} days:</p>
            <table>
                <tr>
                    <th>Name</th>
                    <th>USCIS Number</th>
                    <th>Status</th>
                    <th>Expiry Date</th>
                    <th>Days Remaining</th>
                </tr>
        """
        
        for _, row in expiring_soon.sort_values('Days Until Expiry').iterrows():
            urgent_class = ' class="urgent"' if row['Days Until Expiry'] <= 7 else ''
            html_body += f"""
                <tr{urgent_class}>
                    <td>{row['Name']}</td>
                    <td>{row['USCIS Number']}</td>
                    <td>{row['Status']}</td>
                    <td>{row['Permit Expiry'].strftime('%Y-%m-%d')}</td>
                    <td>{row['Days Until Expiry']}</td>
                </tr>
            """
        
        html_body += """
            </table>
            <p>Please take appropriate action to renew or update these permits before they expire.</p>
            <p>This is an automated message from the USA Immigration Management System.</p>
        </body>
        </html>
        """
        
        return self.send_email(recipient, subject, html_body, html=True)
    
    def send_status_change_notification(self, recipient, immigrant_data, old_status, new_status):
        """
        Send a notification about status changes
        
        Args:
            recipient (str): Email recipient
            immigrant_data (dict): Dictionary with immigrant information
            old_status (str): Previous status
            new_status (str): New status
        
        Returns:
            bool: Whether the email was sent successfully
        """
        subject = f"Status Change Alert: {immigrant_data['Name']}"
        
        html_body = f"""
        <html>
        <head>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                }}
                th, td {{
                    border: 1px solid #dddddd;
                    text-align: left;
                    padding: 8px;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .highlight {{
                    background-color: #ffffcc;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <h2>Status Change Alert</h2>
            <p>The following immigrant has had a status change:</p>
            <table>
                <tr>
                    <th>Field</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Name</td>
                    <td>{immigrant_data['Name']}</td>
                </tr>
                <tr>
                    <td>USCIS Number</td>
                    <td>{immigrant_data['USCIS Number']}</td>
                </tr>
                <tr class="highlight">
                    <td>Previous Status</td>
                    <td>{old_status}</td>
                </tr>
                <tr class="highlight">
                    <td>New Status</td>
                    <td>{new_status}</td>
                </tr>
                <tr>
                    <td>Change Date</td>
                    <td>{datetime.now().strftime('%Y-%m-%d')}</td>
                </tr>
            </table>
            <p>Please review this status change and ensure all appropriate documentation has been processed.</p>
            <p>This is an automated message from the USA Immigration Management System.</p>
        </body>
        </html>
        """
        
        return self.send_email(recipient, subject, html_body, html=True)
    
    def send_weekly_summary(self, recipient, immigrant_data, report_path=None):
        """
        Send a weekly summary of immigration data
        
        Args:
            recipient (str): Email recipient
            immigrant_data (DataFrame): DataFrame with immigrant records
            report_path (str): Path to the summary report PDF
        
        Returns:
            bool: Whether the email was sent successfully
        """
        # Calculate summary statistics
        total_records = len(immigrant_data)
        status_counts = immigrant_data['Status'].value_counts().to_dict() if 'Status' in immigrant_data.columns else {}
        
        # Create expiry summary
        immigrant_data['Permit Expiry'] = pd.to_datetime(immigrant_data['Permit Expiry'], errors='coerce')
        today = datetime.now().date()
        immigrant_data['Days Until Expiry'] = (immigrant_data['Permit Expiry'].dt.date - today).dt.days
        
        # Expiring permits count
        expiring_7_days = len(immigrant_data[(immigrant_data['Days Until Expiry'] >= 0) & (immigrant_data['Days Until Expiry'] <= 7)])
        expiring_30_days = len(immigrant_data[(immigrant_data['Days Until Expiry'] >= 0) & (immigrant_data['Days Until Expiry'] <= 30)])
        
        # Create email body
        subject = f"Weekly Immigration System Summary - {datetime.now().strftime('%Y-%m-%d')}"
        
        html_body = f"""
        <html>
        <head>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-bottom: 20px;
                }}
                th, td {{
                    border: 1px solid #dddddd;
                    text-align: left;
                    padding: 8px;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .section {{
                    margin-top: 20px;
                    margin-bottom: 10px;
                    font-weight: bold;
                }}
                .urgent {{
                    color: red;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <h2>Weekly Immigration System Summary</h2>
            <p>Here is the summary of immigration data for the week ending {datetime.now().strftime('%Y-%m-%d')}:</p>
            
            <div class="section">Total Records</div>
            <table>
                <tr>
                    <th>Total Immigrants</th>
                    <td>{total_records}</td>
                </tr>
            </table>
            
            <div class="section">Status Distribution</div>
            <table>
                <tr>
                    <th>Status</th>
                    <th>Count</th>
                </tr>
        """
        
        for status, count in status_counts.items():
            html_body += f"""
                <tr>
                    <td>{status}</td>
                    <td>{count}</td>
                </tr>
            """
        
        html_body += f"""
            </table>
            
            <div class="section">Permit Expiry Summary</div>
            <table>
                <tr>
                    <th>Timeframe</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td>Expiring in next 7 days</td>
                    <td class="{'urgent' if expiring_7_days > 0 else ''}">{expiring_7_days}</td>
                </tr>
                <tr>
                    <td>Expiring in next 30 days</td>
                    <td>{expiring_30_days}</td>
                </tr>
            </table>
            
            <p>A detailed report is attached to this email (if available).</p>
            <p>This is an automated message from the USA Immigration Management System.</p>
        </body>
        </html>
        """
        
        attachments = [report_path] if report_path and os.path.exists(report_path) else None
        
        return self.send_email(recipient, subject, html_body, attachments=attachments, html=True)

# Create a default instance
default_notifier = EmailNotifier() 