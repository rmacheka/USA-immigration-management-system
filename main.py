from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Optional
import jwt
from jwt import PyJWTError
from passlib.context import CryptContext
from app.database import get_db, engine, Base
from app.auth.models import User, UserRole
from app.auth.dependencies import get_current_user, get_current_active_user, role_required
from app.config import settings
from app.schemas.applicant import Applicant, ApplicantCreate
from app.schemas.application import Application, ApplicationCreate
from app.schemas.permit import Permit, PermitCreate
from app.schemas.document import Document, DocumentCreate
from app.models.applicant import ApplicantStatus
from app.models.application import ApplicationStatus, ApplicationType
from app.models.permit import PermitStatus, PermitType
from app.models.document import DocumentStatus, DocumentType
from app.services.applicant_service import ApplicantService
from app.services.application_service import ApplicationService
from app.services.permit_service import PermitService
from app.services.document_service import DocumentService
from app.services.report_service import ReportService
from app.utils.geocoding import verify_address
from app.utils.report_generator import generate_report
import pandas as pd

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize services
applicant_service = ApplicantService()
application_service = ApplicationService()
permit_service = PermitService()
document_service = DocumentService()
report_service = ReportService()

# Initialize FastAPI app
app = FastAPI(title="USA Immigration System")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication routes
@app.post("/token")
async def login_for_access_token(
    username: str,
    password: str,
    db: Session = Depends(get_db)
):
    """Login to get access token"""
    user = applicant_service.authenticate_user(db, username, password)
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.encode(
        {"sub": user.username, "exp": datetime.utcnow() + access_token_expires},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return {
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role.value,
        "is_active": current_user.is_active
    }

def validate_phone_number(phone: str) -> bool:
    """Validate phone number format"""
    import re
    pattern = r'^\+?1?\d{9,15}$'
    return bool(re.match(pattern, phone))

def validate_date_format(date_str: str) -> bool:
    """Validate if the date string is in YYYY-MM-DD format and is a valid date"""
    try:
        # First check if the format is correct
        datetime.strptime(date_str, '%Y-%m-%d')
        # Then check if it's a valid date (e.g., not November 31st)
        year, month, day = map(int, date_str.split('-'))
        datetime(year, month, day)
        return True
    except (ValueError, TypeError):
        return False

def load_data():
    try:
        return pd.read_csv("data/records.csv")
    except FileNotFoundError:
        return pd.DataFrame(columns=["Name", "Phone", "Profession", "Address", "Nationality", "Permit Expiry", "Status"])

def save_data(df):
    df.to_csv("data/records.csv", index=False)

def add_record(df):
    name = input("Enter name: ")
    phone = input("Enter phone number: ")
    if not validate_phone_number(phone):
        print("Invalid phone number!")
        return df
    profession = input("Enter profession: ")
    address = input("Enter address: ")
    if not verify_address(address):
        print("Invalid address!")
        return df
    nationality = input("Enter nationality: ")
    permit_expiry = input("Enter permit expiry (YYYY-MM-DD): ")
    status = input("Enter status (Permanent/Temporary/Expired/Illegal): ")
    new_record = pd.DataFrame([{
        "Name": name, "Phone": phone, "Profession": profession, "Address": address,
        "Nationality": nationality, "Permit Expiry": permit_expiry, "Status": status
    }])
    
    # Add the new record and save
    df = pd.concat([df, new_record], ignore_index=True)
    save_data(df)
    
    # Show confirmation message
    print("\n=== Record Added Successfully ===")
    print(f"Name: {name}")
    print(f"Phone: {phone}")
    print(f"Profession: {profession}")
    print(f"Address: {address}")
    print(f"Nationality: {nationality}")
    print(f"Permit Expiry: {permit_expiry}")
    print(f"Status: {status}")
    print("=" * 50)
    
    # Display updated records table
    print("\n=== Updated Records Table ===")
    print(df.to_string(index=False))
    print("=" * 50)
    
    return df

def search_by_phone(phone: str) -> dict:
    """Search for records by phone number in records.csv, applications.csv, and permits.csv"""
    try:
        # Clean the phone number (remove spaces and ensure proper format)
        phone = phone.strip().replace(" ", "")
        if not phone.startswith("+"):
            phone = "+" + phone

        print(f"\nSearching for phone number: {phone}")
        
        # First check records.csv for basic information
        try:
            records_df = pd.read_csv("data/records.csv")
            records_df['Phone'] = records_df['Phone'].astype(str).str.strip()
            records_df['Phone'] = records_df['Phone'].apply(lambda x: '+' + x if not x.startswith('+') else x)
            person = records_df[records_df["Phone"] == phone]
            
            if not person.empty:
                p = person.iloc[0]
                print("\n=== Individual Details ===")
                print(f"Name: {p['Name']}")
                print(f"Phone: {p['Phone']}")
                print(f"Nationality: {p['Nationality']}")
                print(f"Profession: {p['Profession']}")
                print(f"Address: {p['Address']}")
                print(f"Permit Expiry: {p['Permit Expiry']}")
                print(f"Status: {p['Status']}")
                print("=" * 50)
                
                # Check applications.csv for application status
                try:
                    applications_df = pd.read_csv("data/applications.csv")
                    applications_df['Phone'] = applications_df['Phone'].astype(str).str.strip()
                    applications_df['Phone'] = applications_df['Phone'].apply(lambda x: '+' + x if not x.startswith('+') else x)
                    application = applications_df[applications_df["Phone"] == phone]
                    
                    if not application.empty:
                        app = application.iloc[0]
                        print("\n=== Application Status ===")
                        print(f"Application Type: {app['Application Type']}")
                        print(f"Submission Date: {app['Submission Date']}")
                        print(f"Status: {app['Status']}")
                        print("=" * 50)
                    else:
                        print("\nNote: No application records found for this individual.")
                except Exception as e:
                    print(f"\nNote: Could not access application details: {str(e)}")
                
                # Then check permits.csv for permit details
                try:
                    permits_df = pd.read_csv("data/permits.csv")
                    permits_df['Phone'] = permits_df['Phone'].astype(str).str.strip()
                    permit = permits_df[permits_df["Phone"] == phone]
                    
                    if not permit.empty:
                        p_permit = permit.iloc[0]
                        print("\n=== Permit Details ===")
                        print(f"Permit Type: {p_permit['Permit Type']}")
                        print(f"Passport Number: {p_permit['Passport Number']}")
                        print(f"Issue Date: {p_permit['Issue Date']}")
                        print(f"Expiry Date: {p_permit['Expiry Date']}")
                        print(f"Status: {p_permit['Status']}")
                        print(f"Nationality: {p_permit['Nationality']}")
                        print(f"Profession: {p_permit['Profession']}")
                        print(f"Address: {p_permit['Address']}")
                        print("=" * 50)
                    else:
                        print("\nNote: No permit details found for this individual.")
                except Exception as e:
                    print(f"\nNote: Could not access permit details: {str(e)}")
                
                return {
                    "found": True,
                    "person": p.to_dict()
                }
            else:
                # If not found in records.csv, check permits.csv
                try:
                    permits_df = pd.read_csv("data/permits.csv")
                    permits_df['Phone'] = permits_df['Phone'].astype(str).str.strip()
                    permit = permits_df[permits_df["Phone"] == phone]
                    
                    if not permit.empty:
                        p_permit = permit.iloc[0]
                        print("\n=== Individual Details (from Permits) ===")
                        print(f"Name: {p_permit['Name']}")
                        print(f"Phone: {p_permit['Phone']}")
                        print(f"Nationality: {p_permit['Nationality']}")
                        print(f"Profession: {p_permit['Profession']}")
                        print(f"Address: {p_permit['Address']}")
                        print(f"Passport Number: {p_permit['Passport Number']}")
                        print(f"Permit Type: {p_permit['Permit Type']}")
                        print(f"Issue Date: {p_permit['Issue Date']}")
                        print(f"Expiry Date: {p_permit['Expiry Date']}")
                        print(f"Status: {p_permit['Status']}")
                        print("=" * 50)
                        
                        # Check applications for this person
                        try:
                            applications_df = pd.read_csv("data/applications.csv")
                            applications_df['Phone'] = applications_df['Phone'].astype(str).str.strip()
                            applications_df['Phone'] = applications_df['Phone'].apply(lambda x: '+' + x if not x.startswith('+') else x)
                            application = applications_df[applications_df["Phone"] == phone]
                            
                            if not application.empty:
                                app = application.iloc[0]
                                print("\n=== Application Status ===")
                                print(f"Application Type: {app['Application Type']}")
                                print(f"Submission Date: {app['Submission Date']}")
                                print(f"Status: {app['Status']}")
                                print("=" * 50)
                        except Exception as e:
                            print(f"\nNote: Could not access application details: {str(e)}")
                        
                        return {
                            "found": True,
                            "person": p_permit.to_dict()
                        }
                    else:
                        print(f"\nNo records found with phone number: {phone}")
                        return {
                            "found": False,
                            "message": f"No records found with phone number: {phone}"
                        }
                except Exception as e:
                    print(f"Error reading permits.csv: {str(e)}")
                    return {
                        "found": False,
                        "message": f"Error reading permits: {str(e)}"
                    }
        except Exception as e:
            print(f"Error reading records.csv: {str(e)}")
            return {
                "found": False,
                "message": f"Error reading records: {str(e)}"
            }
    except Exception as e:
        print(f"Error in search_by_phone: {str(e)}")
        return {
            "found": False,
            "message": f"Error searching records: {str(e)}"
        }

def search_permit_status(search_type: str, search_value: str) -> dict:
    """Search for permit status by phone number, name, or passport number"""
    try:
        # Read permits data
        permits_df = pd.read_csv("data/permits.csv")
        
        # Search based on type
        if search_type == "phone":
            result = permits_df[permits_df["Phone"] == search_value]
        elif search_type == "name":
            result = permits_df[permits_df["Name"].str.lower() == search_value.lower()]
        elif search_type == "passport":
            result = permits_df[permits_df["Passport Number"] == search_value]
        else:
            return {
                "found": False,
                "message": "Invalid search type. Please use 'phone', 'name', or 'passport'."
            }
        
        if result.empty:
            return {
                "found": False,
                "message": f"No permit records found for {search_type}: {search_value}"
            }
        
        # Convert result to dictionary
        permit_data = result.iloc[0].to_dict()
        
        # Format the response
        response = {
            "found": True,
            "permit_details": {
                "name": permit_data["Name"],
                "phone": permit_data["Phone"],
                "passport_number": permit_data["Passport Number"],
                "permit_type": permit_data["Permit Type"],
                "status": permit_data["Status"],
                "issue_date": permit_data["Issue Date"],
                "expiry_date": permit_data["Expiry Date"],
                "nationality": permit_data["Nationality"],
                "profession": permit_data["Profession"],
                "address": permit_data["Address"]
            }
        }
        
        return response
    except Exception as e:
        return {
            "found": False,
            "message": f"Error searching permit status: {str(e)}"
        }


def main():
    df = load_data()
    while True:
        print("\n1. Add Record\n2. Search by Phone\n3. Generate Report\n4. Check Permit Status\n5. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            df = add_record(df)
            retry = input("\nWould you like to add another record? (y/n): ")
            if retry.lower() != 'y':
                continue
            while retry.lower() == 'y':
                df = add_record(df)
                retry = input("\nWould you like to add another record? (y/n): ")
        elif choice == "2":
            phone = input("Enter phone number to search (e.g., +1445566778): ")
            result = search_by_phone(phone)
            
            if not result["found"]:
                print(result["message"])
                retry = input("Would you like to try another search? (y/n): ")
                if retry.lower() != 'y':
                    break
            else:
                retry = input("\nWould you like to search for another phone number? (y/n): ")
                if retry.lower() != 'y':
                    break
        elif choice == "3":
            while True:
                report_type = input("Enter report type (applications/permits): ").lower()
                if report_type not in ['applications', 'permits']:
                    print("Invalid report type. Please enter 'applications' or 'permits'.")
                    continue

                # Validate start and end dates
                start_date = input("Enter start date (YYYY-MM-DD): ").strip()
                if not validate_date_format(start_date):
                    print("Error: Invalid start date format.")
                    continue

                end_date = input("Enter end date (YYYY-MM-DD): ").strip()
                if not validate_date_format(end_date):
                    print("Error: Invalid end date format.")
                    continue

                start = datetime.strptime(start_date, '%Y-%m-%d')
                end = datetime.strptime(end_date, '%Y-%m-%d')

                # Ask if user wants to search for a specific person
                search_individual = input("Would you like to search for a specific person? (y/n): ").lower()
                search_by = None
                search_value = None

                if search_individual == 'y':
                    search_by = input("Search by (name/phone): ").lower()
                    if search_by not in ['name', 'phone']:
                        print("Invalid search criteria. Using date range only.")
                        search_by = None
                    else:
                        search_value = input(f"Enter {search_by}: ").strip()

                try:
                    # Load data with proper CSV quoting
                    permits_df = pd.read_csv("data/permits.csv", quotechar='"')
                    applications_df = pd.read_csv("data/applications.csv", quotechar='"')

                    # Parse dates
                    permits_df['Issue Date'] = pd.to_datetime(permits_df['Issue Date'], errors='coerce')
                    permits_df['Expiry Date'] = pd.to_datetime(permits_df['Expiry Date'], errors='coerce')
                    applications_df['Submission Date'] = pd.to_datetime(applications_df['Submission Date'], errors='coerce')

                    print("\n=== Report Results ===")
                    print(f"Date Range: {start_date} to {end_date}")

                    if report_type == 'permits':
                        # Filter permits that overlap with the given time period
                        valid_permits = permits_df[
                            (permits_df['Issue Date'].notna()) &  # Ensure Issue Date is not null
                            (permits_df['Expiry Date'].notna()) &  # Ensure Expiry Date is not null
                            (
                                ((permits_df['Issue Date'] <= end) & (permits_df['Expiry Date'] >= start)) |  # Permit overlaps with period
                                ((permits_df['Issue Date'] >= start) & (permits_df['Issue Date'] <= end)) |   # Permit issued during period
                                ((permits_df['Expiry Date'] >= start) & (permits_df['Expiry Date'] <= end))    # Permit expires during period
                            )
                        ]
                        print("\n=== Permits Statistics ===")
                        print(f"Total Permits: {len(valid_permits)}")
                        if not valid_permits.empty:
                            print("\nPermit Types Distribution:")
                            print(valid_permits['Permit Type'].value_counts())
                            print("\nStatus Distribution:")
                            print(valid_permits['Status'].value_counts())
                            
                            print("\n=== Permits Table ===")
                            permits_table = valid_permits[[
                                'Name', 'Phone', 'Passport Number', 'Permit Type',
                                'Status', 'Issue Date', 'Expiry Date', 'Nationality',
                                'Profession', 'Address'
                            ]].copy()
                            permits_table['Issue Date'] = permits_table['Issue Date'].dt.strftime('%Y-%m-%d')
                            permits_table['Expiry Date'] = permits_table['Expiry Date'].dt.strftime('%Y-%m-%d')
                            print(permits_table.to_string(index=False))
                        else:
                            print("\nNo permits found in the specified time period.")

                    elif report_type == 'applications':
                        # Filter applications submitted during the given time period
                        valid_applications = applications_df[
                            (applications_df['Submission Date'].notna()) &  # Ensure Submission Date is not null
                            (applications_df['Submission Date'] >= start) & 
                            (applications_df['Submission Date'] <= end)
                        ]
                        print("\n=== Applications Statistics ===")
                        print(f"Total Applications: {len(valid_applications)}")
                        if not valid_applications.empty:
                            print("\nApplication Types Distribution:")
                            print(valid_applications['Application Type'].value_counts())
                            print("\nStatus Distribution:")
                            print(valid_applications['Status'].value_counts())
                            
                            print("\n=== Applications Table ===")
                            applications_table = valid_applications[[
                                'Name', 'Phone', 'Application Type',
                                'Submission Date', 'Status'
                            ]].copy()
                            applications_table['Submission Date'] = applications_table['Submission Date'].dt.strftime('%Y-%m-%d')
                            print(applications_table.to_string(index=False))
                        else:
                            print("\nNo applications found in the specified time period.")

                except Exception as e:
                    print(f"Error generating report: {str(e)}")
                    retry = input("Would you like to try again? (y/n): ")
                    if retry.lower() != 'y':
                        break
                    continue
        elif choice == "4":
            while True:
                print("\nSearch Permit Status by:")
                print("1. Phone Number")
                print("2. Name")
                print("3. Passport Number")
                print("4. Back to Main Menu")
                
                search_choice = input("Enter your choice (1-4): ")
                
                if search_choice == "4":
                    break
                
                if search_choice not in ["1", "2", "3"]:
                    print("Invalid choice. Please try again.")
                    continue
                
                search_type = {
                    "1": "phone",
                    "2": "name",
                    "3": "passport"
                }[search_choice]
                
                search_value = input(f"Enter {search_type}: ")
                result = search_permit_status(search_type, search_value)
                
                if not result["found"]:
                    print(result["message"])
                    retry = input("Would you like to try another search? (y/n): ")
                    if retry.lower() != 'y':
                        break
                else:
                    print("\nPermit Details:")
                    details = result["permit_details"]
                    print(f"Name: {details['name']}")
                    print(f"Phone: {details['phone']}")
                    print(f"Passport Number: {details['passport_number']}")
                    print(f"Permit Type: {details['permit_type']}")
                    print(f"Status: {details['status']}")
                    print(f"Issue Date: {details['issue_date']}")
                    print(f"Expiry Date: {details['expiry_date']}")
                    print(f"Nationality: {details['nationality']}")
                    print(f"Profession: {details['profession']}")
                    print(f"Address: {details['address']}")
                    
                    retry = input("\nWould you like to search for another permit? (y/n): ")
                    if retry.lower() != 'y':
                        break
        elif choice == "5":
            save_data(df)
            break
        else:
            print("Invalid selection. Please enter a number between 1 and 5.")
            retry = input("Would you like to try again? (y/n): ")
            if retry.lower() != 'y':
                break

# Applicant routes
@app.post("/applicants/", response_model=Applicant)
async def create_applicant(
    first_name: str,
    last_name: str,
    date_of_birth: datetime,
    nationality: str,
    passport_number: str,
    email: str,
    phone_number: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.OFFICER]))
):
    """Create a new applicant"""
    return applicant_service.create_applicant(
        db=db,
        first_name=first_name,
        last_name=last_name,
        date_of_birth=date_of_birth,
        nationality=nationality,
        passport_number=passport_number,
        email=email,
        phone_number=phone_number
    )

@app.get("/applicants/{applicant_id}", response_model=Applicant)
async def get_applicant(
    applicant_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get applicant by ID"""
    return applicant_service.get_applicant(db, applicant_id)

@app.get("/applicants/passport/{passport_number}", response_model=Applicant)
async def get_applicant_by_passport(
    passport_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get applicant by passport number"""
    return applicant_service.get_applicant_by_passport(db, passport_number)

@app.put("/applicants/{applicant_id}/status")
async def update_applicant_status(
    applicant_id: int,
    status: ApplicantStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.OFFICER]))
):
    """Update applicant status"""
    return applicant_service.update_applicant_status(db, applicant_id, status)

# Application routes
@app.post("/applications/", response_model=Application)
async def create_application(
    applicant_id: int,
    application_type: ApplicationType,
    submission_date: datetime,
    status: ApplicationStatus = ApplicationStatus.PENDING,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new application"""
    return application_service.create_application(
        db=db,
        applicant_id=applicant_id,
        application_type=application_type,
        submission_date=submission_date,
        status=status
    )

@app.get("/applications/{application_id}", response_model=Application)
async def get_application(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get application by ID"""
    return application_service.get_application(db, application_id)

@app.put("/applications/{application_id}/status")
async def update_application_status(
    application_id: int,
    status: ApplicationStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.OFFICER]))
):
    """Update application status"""
    return application_service.update_application_status(db, application_id, status)

# Permit routes
@app.post("/permits/", response_model=Permit)
async def create_permit(
    application_id: int,
    permit_type: PermitType,
    issue_date: datetime,
    expiry_date: datetime,
    is_renewable: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.OFFICER]))
):
    """Create a new permit"""
    return permit_service.create_permit(
        db=db,
        application_id=application_id,
        permit_type=permit_type,
        issue_date=issue_date,
        expiry_date=expiry_date,
        is_renewable=is_renewable
    )

@app.get("/permits/{permit_id}", response_model=Permit)
async def get_permit(
    permit_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get permit by ID"""
    return permit_service.get_permit(db, permit_id)

@app.put("/permits/{permit_id}/status")
async def update_permit_status(
    permit_id: int,
    status: PermitStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.OFFICER]))
):
    """Update permit status"""
    return permit_service.update_permit_status(db, permit_id, status)

# Document routes
@app.post("/documents/", response_model=Document)
async def create_document(
    applicant_id: int,
    document_type: DocumentType,
    file_path: str,
    upload_date: datetime,
    status: DocumentStatus = DocumentStatus.PENDING,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new document"""
    return document_service.create_document(
        db=db,
        applicant_id=applicant_id,
        document_type=document_type,
        file_path=file_path,
        upload_date=upload_date,
        status=status
    )

@app.get("/documents/{document_id}", response_model=Document)
async def get_document(
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get document by ID"""
    return document_service.get_document(db, document_id)

@app.put("/documents/{document_id}/status")
async def update_document_status(
    document_id: int,
    status: DocumentStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.OFFICER]))
):
    """Update document status"""
    return document_service.update_document_status(db, document_id, status)

# Report routes
@app.get("/reports/applications")
async def get_applications_report(
    start_date: datetime,
    end_date: datetime,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERVISOR]))
):
    """Generate applications report"""
    return report_service.generate_applications_report(db, start_date, end_date)

@app.get("/reports/permits")
async def get_permits_report(
    start_date: datetime,
    end_date: datetime,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERVISOR]))
):
    """Generate permits report"""
    return report_service.generate_permits_report(db, start_date, end_date)

# Utility endpoints
@app.post("/verify-address")
async def verify_address_endpoint(
    address: str,
    current_user: User = Depends(get_current_active_user)
):
    """Verify address using geocoding service"""
    return verify_address(address)

@app.get("/generate-report/{report_type}")
async def generate_report_endpoint(
    report_type: str,
    parameters: dict,
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERVISOR]))
):
    """Generate custom report"""
    return generate_report(report_type, parameters)

if __name__ == "__main__":
    main()