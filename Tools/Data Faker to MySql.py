"""
Script Purpose: 
This script generates and inserts a specified number of fake records into a MySQL database. 
It can either prompt the user for the number of records (between 1-500) and database credentials,
or accept them as command-line parameters.
Additionally, users can choose to create a new database and table if they do not exist.
If some parameters are provided, the script will display them in a wizard and allow modification.

Agreement Notes:
- This script is intended for testing and development purposes only.
- Do not use real personal data in any production environment.
- Ensure compliance with data protection regulations before use.

Dependencies:
- mysql-connector-python
- faker

The script will check for missing dependencies and prompt the user before installing them.
"""

import subprocess
import sys
import argparse
import random
import importlib.util


# Check if a package is installed
def is_package_installed(package):
    try:
        subprocess.run([sys.executable, "-m", "pip", "show", package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

# Check for missing dependencies and prompt user before installing
def check_and_install_dependencies():
    required_packages = ["mysql-connector-python", "faker","getpass"]
    missing_packages = [pkg for pkg in required_packages if not is_package_installed(pkg)]
    
    if missing_packages:
        print(f"The following dependencies are missing: {', '.join(missing_packages)}")
        install = input("Would you like to install them? (yes/no) [yes]: ").strip().lower() or "yes"
        if install == "yes":
            for package in missing_packages:
                subprocess.run([sys.executable, "-m", "pip", "install", package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("Dependencies installed successfully.")
        else:
            print("Missing dependencies were not installed. The script may not run correctly.")
            sys.exit(1)

check_and_install_dependencies()

import mysql.connector
import faker
import getpass
# Initialize Faker
generator = faker.Faker()

# Argument parser
parser = argparse.ArgumentParser(description="Generate and insert fake data into MySQL database.")
parser.add_argument("--num_rows", type=int, help="Number of rows to insert (1-500)")
parser.add_argument("--db_host", type=str, help="Database host")
parser.add_argument("--db_user", type=str, help="Database user")
parser.add_argument("--db_password", type=str, help="Database password")
parser.add_argument("--db_name", type=str, help="Database name")
parser.add_argument("--create_db", action='store_true', help="Create database and table if they do not exist")
args = parser.parse_args()

# Collect parameters, showing defaults if provided
num_rows = args.num_rows if args.num_rows else int(input(f"Enter the number of rows to insert (1-500) [{args.num_rows if args.num_rows else ''}]: ") or args.num_rows or 100)
db_host = args.db_host if args.db_host else input(f"Enter the database host [{args.db_host if args.db_host else 'localhost'}]: ") or "localhost"
db_user = args.db_user if args.db_user else input(f"Enter the database user [{args.db_user if args.db_user else 'root'}]: ") or "root"
db_password = args.db_password if args.db_password else getpass.getpass("Enter the database password(input characters are hidden): ")
db_name = args.db_name if args.db_name else input(f"Enter the database name [{args.db_name if args.db_name else 'test_db'}]: ") or "test_db"

# Connect to MySQL to check if database exists
conn = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password
)
cursor = conn.cursor()
cursor.execute("SHOW DATABASES")
databases = [db[0] for db in cursor.fetchall()]

if db_name not in databases:
    create_db = input(f"The database '{db_name}' does not exist. Would you like to create it? (yes/no) [no]: ").strip().lower() == "no"
    if create_db == "yes":
        cursor.execute(f"CREATE DATABASE {db_name}")
    else:
        print("The specified database does not exist and cannot be created. Please verify the database name and try again.")
        sys.exit(1)

# Connect to the selected database
conn = mysql.connector.connect(
    host=db_host,
    user=db_user,
    password=db_password,
    database=db_name
)
cursor = conn.cursor()

# Create table if necessary
cursor.execute("""
CREATE TABLE IF NOT EXISTS fake_data (
    first_name VARCHAR(50),
    middle_name VARCHAR(50),
    last_name VARCHAR(50),
    gender VARCHAR(20),
    date_of_birth DATE,
    marital_status VARCHAR(20),
    nationality VARCHAR(50),
    email_address VARCHAR(100),
    secondary_email_address VARCHAR(100),
    phone_number VARCHAR(20),
    secondary_phone_number VARCHAR(20),
    street_address VARCHAR(200),
    city VARCHAR(50),
    state_province VARCHAR(50),
    postal_code VARCHAR(20),
    country VARCHAR(50),
    passport_number VARCHAR(20),
    drivers_license_number VARCHAR(20),
    health_insurance_number VARCHAR(20),
    medical_record_number VARCHAR(20),
    blood_type VARCHAR(5),
    allergies VARCHAR(100),
    chronic_conditions VARCHAR(100),
    medications VARCHAR(100),
    job_title VARCHAR(100),
    department VARCHAR(50),
    employee_id VARCHAR(20),
    employer_name VARCHAR(100),
    work_email_address VARCHAR(100),
    student_id VARCHAR(20),
    university_college_name VARCHAR(100),
    degree VARCHAR(10),
    graduation_year INT,
    credit_card_number VARCHAR(20),
    bank_account_number VARCHAR(30),
    iban VARCHAR(34)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""")

# SQL Insert Statement
dml = """
INSERT INTO fake_data (
    first_name, middle_name, last_name, gender, date_of_birth, marital_status, nationality,
    email_address, secondary_email_address, phone_number, secondary_phone_number, street_address,
    city, state_province, postal_code, country, passport_number, drivers_license_number,
    health_insurance_number, medical_record_number, blood_type, allergies, chronic_conditions,
    medications, job_title, department, employee_id, employer_name, work_email_address,
    student_id, university_college_name, degree, graduation_year, credit_card_number,
    bank_account_number, iban
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

# Generate and insert rows
for _ in range(num_rows):
    values = (
        generator.first_name(), generator.first_name(), generator.last_name(),
        random.choice(["Male", "Female", "Non-binary"]),
        generator.date_of_birth(minimum_age=18, maximum_age=70).strftime("%Y-%m-%d"),
        random.choice(["Single", "Married", "Divorced", "Widowed"]),
        generator.country(), generator.email(), generator.email(),
        generator.phone_number(), generator.phone_number(), generator.street_address(),
        generator.city(), generator.state(), generator.postcode(), generator.country(),
        generator.bothify(text="P#########"), generator.bothify(text="D########"),
        generator.bothify(text="H#########"), generator.bothify(text="M#########"),
        random.choice(["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]),
        random.choice(["None", "Peanuts", "Penicillin", "Pollen", "Dust", "Shellfish"]),
        random.choice(["None", "Diabetes", "Hypertension", "Asthma", "Arthritis"]),
        random.choice(["None", "Metformin", "Lisinopril", "Ibuprofen", "Paracetamol"]),
        generator.job(), generator.word().capitalize(), generator.bothify(text="E########"),
        generator.company(), generator.company_email(), generator.bothify(text="S########"),
        generator.company(), random.choice(["BSc", "MSc", "PhD", "BA", "MA"]),
        random.randint(2000, 2025), generator.credit_card_number(), generator.bban(), generator.iban()
    )
    cursor.execute(dml, values)

conn.commit()
cursor.close()
conn.close()
print(f"{num_rows} rows inserted into fake_data table.")
