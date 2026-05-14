#!/usr/bin/env python3
# This project is made by Lakshan Siriwardhana in order to manage security incidents
# and provide insights to top management.

from io import Reader
import mysql.connector 
import requests # This will be used to fetch data from the internet
import json # This will be used to convert the data to JSON format
import csv # This will be used to read and write CSV files
import datetime
import pandas as pd
import pdfplumber
from docx import Document

# timestamp for all CVEs in this batch
event_time = datetime.datetime.now()

# Connect to MySQL
security_db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="umaya@15308",
    database="Security_Incident_Management"
)

print("Database connection successful:", security_db)

# Create a database 
mycursor = security_db.cursor() 
#mycursor.execute("CREATE DATABASE Security_Incident_Management")

# Create cursor
mycursor = security_db.cursor()

# Show databases
mycursor = security_db.cursor()
mycursor.execute("SHOW DATABASES") # this will show the Databases.
for x in mycursor:
    print(x)

mycursor = security_db.cursor()

# Add CVSS Data from NIST Database from an API

#mycursor.execute("""
#CREATE TABLE IF NOT EXISTS cvss_data (
#    id INT AUTO_INCREMENT PRIMARY KEY,
#    cve_id VARCHAR(50),
#    published_date VARCHAR(50),
#    last_modified VARCHAR(50),
#    description TEXT
#)
#""")    

# Fetch API data
#response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
#data = response.json()

#mycursor.execute("USE security_incident_management") # this is to use the database created earlier

# Extract vulnerabilities
#vulnerabilities = data.get("vulnerabilities", [])

# Prepare data for processing
#data_to_insert = []

#for vuln in vulnerabilities:
#    cve = vuln.get("cve", {})
#    cve_id = cve.get("id")
#    published_date = cve.get("published")
#    last_modified = cve.get("lastModified")
    # Extract description safely
#    descriptions = cve.get("descriptions", [])
#    description_text = ""
#    if descriptions:
#        description_text = descriptions[0].get("value", "")
    

    # Add tuple
#    data_to_insert.append((
#        cve_id,
#        published_date,
#        last_modified,
#        description_text,
#    ))

# Insert in to database 
#insert_query = """
#INSERT INTO cvss_data (cve_id, published_date, last_modified, description)
#VALUES (%s, %s, %s, %s)
#"""

# Batch insert
#mycursor.executemany(insert_query, data_to_insert)
#security_db.commit()

print(f"{mycursor.rowcount} CVE rows inserted successfully.")

# Add Incident Data from CSV

#mycursor.execute("""
#CREATE TABLE IF NOT EXISTS Incident_data (
#    id INT AUTO_INCREMENT PRIMARY KEY,
#    date DATE,
#    incident_name VARCHAR(255),
#    occurred_timestamp BIGINT,
#    attended_engineer VARCHAR(255),
#    cve_number VARCHAR(255),
#    attack_type VARCHAR(255),
#    severity VARCHAR(255),
#    damage_usd DECIMAL(15,2)
#)
#""")

# Prepare the insert query
insert_query = """
INSERT INTO Incident_data
(date, incident_name, occurred_timestamp, attended_engineer, cve_number, attack_type, severity, damage_usd)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
"""

# Read CSV and prepare data
data_to_insert = []
with open("security_incidents.csv", newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        data_to_insert.append((
            row['date'],
            row['Incident_name'],
            int(row['occurred_timestamp']),
            row['attended_engineer'],
            row['cve_number'],
            row['attack_type'],
            row['severity'],
            float(row['damage_usd'])
        ))

# Execute many inserts at once
mycursor.executemany(insert_query, data_to_insert)

# Commit once
security_db.commit()
print(f"{mycursor.rowcount} rows Incident records inserted successfully.")

# Close the connection
mycursor.close()
security_db.close()


# Add Customer Data from PDF
#create Customer data table 
#mycursor.execute("""
#CREATE TABLE IF NOT EXISTS Customer_data (
#    id INT AUTO_INCREMENT PRIMARY KEY,
#    name VARCHAR(100),
#    email VARCHAR(100),
#    location VARCHAR(100),
#    phone VARCHAR(20)
#);
#""")

#with pdfplumber.open("customers_List.pdf") as pdf:
#    for page in pdf.pages:
#        tables = page.extract_tables() # extract tables from each page

#        for table in tables:
#            for row in table[1:]:  # skip header of the PDF table
#                name, email, location, phone = row
#
#                mycursor.execute("""
#                INSERT INTO Customer_data (name, email, location, phone)
#                VALUES (%s, %s, %s, %s)
#                """, (name, email, location, phone))

#security_db.commit() # save changes to database
print(f"{mycursor.rowcount} rows Customer data inserted successfully.")

# Asset Data from docx
#doc = Document("Asset_Inventory.docx")

#for table in doc.tables:
#    for row in table.rows:
#        data = [cell.text.strip() for cell in row.cells]

#mycursor.execute("""
#CREATE TABLE IF NOT EXISTS Asset_Inventory (
#    id INT AUTO_INCREMENT PRIMARY KEY,
#    Asset_ID VARCHAR(100),
#    Asset_Name VARCHAR(100),
#    Category VARCHAR(100),
#    Owner VARCHAR(20),
#    Location VARCHAR(100),
#    IP_Address VARCHAR(100),
#    Serial_Number VARCHAR(100),
#    Purchase_Date DATE,
#    Warranty_Expiry DATE,
#    Status VARCHAR(20),
#    CVE_Risk VARCHAR(20)
#)
#""")

#Asset_Inventory = []

#for table in doc.tables:
#    for i, row in enumerate(table.rows):
#        if i == 0:
#            continue  # skip header

#        cells = [cell.text.strip() for cell in row.cells]

#        if len(cells) == 11:
#            Asset_ID, Asset_Name, Category, Owner, Location, IP_Address, Serial_Number, Purchase_Date, Warranty_Expiry, Status, CVE_Risk = cells
#            Asset_Inventory.append((Asset_ID, Asset_Name, Category, Owner, Location, IP_Address, Serial_Number, Purchase_Date, Warranty_Expiry, Status, CVE_Risk))

#cursor = security_db.cursor()

#for record in Asset_Inventory:
#    cursor.execute("""
#        INSERT INTO Asset_Inventory (Asset_ID, Asset_Name, Category, Owner, Location, IP_Address, Serial_Number, Purchase_Date, Warranty_Expiry, Status, CVE_Risk)
#        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
#    """, record)

#security_db.commit()

print(f"{mycursor.rowcount} rows Asset Inventory data inserted successfully!")