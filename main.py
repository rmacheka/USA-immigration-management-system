import pandas as pd
from utils.data_validation import validate_phone_number
from utils.geocoding import verify_address
from utils.report_generator import generate_report

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
        return
    profession = input("Enter profession: ")
    address = input("Enter address: ")
    if not verify_address(address):
        print("Invalid address!")
        return
    nationality = input("Enter nationality: ")
    permit_expiry = input("Enter permit expiry (YYYY-MM-DD): ")
    status = input("Enter status (Permanent/Temporary/Expired/Illegal): ")
    new_record = pd.DataFrame([{
        "Name": name, "Phone": phone, "Profession": profession, "Address": address,
        "Nationality": nationality, "Permit Expiry": permit_expiry, "Status": status
    }])
    return pd.concat([df, new_record], ignore_index=True)

def search_by_phone(df, phone):
    return df[df["Phone"] == phone]

def main():
    df = load_data()
    while True:
        print("\n1. Add Record\n2. Search by Phone\n3. Generate Report\n4. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            df = add_record(df)
        elif choice == "2":
            phone = input("Enter phone number to search: ")
            print(search_by_phone(df, phone))
        elif choice == "3":
            generate_report(df)
        elif choice == "4":
            save_data(df)
            break

if __name__ == "__main__":
    main()