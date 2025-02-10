def generate_report(df):
    print("\n--- Immigration Report ---")
    print(f"Total Records: {len(df)}")
    print(f"Permanent Residents: {len(df[df['Status'] == 'Permanent'])}")
    print(f"Temporary Visa Holders: {len(df[df['Status'] == 'Temporary'])}")
    print(f"Expired Permits: {len(df[df['Status'] == 'Expired'])}")
    print(f"Illegal Immigrants: {len(df[df['Status'] == 'Illegal'])}")
    print("\n--- Detailed Records ---")
    