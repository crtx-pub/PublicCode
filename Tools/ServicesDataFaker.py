import subprocess
import sys
import argparse
import random

import getpass


# Check if a package is installed
def is_package_installed(package):
    try:
        subprocess.run([sys.executable, "-m", "pip", "show", package], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


# Check for missing dependencies and prompt user before installing
def check_and_install_dependencies():
    # Add any extra packages needed for the different services here
    required_packages = ["mysql-connector-python", "faker", "psycopg2-binary", "boto3","maskpass"]
    missing_packages = [pkg for pkg in required_packages if not is_package_installed(pkg)]

    if missing_packages:
        print(f"The following dependencies are missing: {', '.join(missing_packages)}")
        install = input("Would you like to install them? (yes/no) [yes]: ").strip().lower() or "yes"
        if install == "yes":
            for package in missing_packages:
                subprocess.run([sys.executable, "-m", "pip", "install", package], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            print("Dependencies installed successfully.")
        else:
            print("Missing dependencies were not installed. The script may not run correctly.")
            sys.exit(1)


check_and_install_dependencies()
import maskpass

try:
    import faker
except ImportError:
    # If for any reason Faker wasn't installed, we cannot proceed
    print("Faker library missing and could not be installed. Exiting.")
    sys.exit(1)


# Original comment: # Initialize Faker
# We'll place it later inside generate_fake_record if needed.

# ------------------ DATA GENERATION FUNCTION ------------------
def generate_fake_record(generator):
    """
    Returns a dictionary containing fields for a single synthetic record.
    """
    return {
        "first_name": generator.first_name(),
        "middle_name": generator.first_name(),
        "last_name": generator.last_name(),
        "gender": random.choice(["Male", "Female", "Non-binary"]),
        "date_of_birth": generator.date_of_birth(minimum_age=18, maximum_age=70).strftime("%Y-%m-%d"),
        "marital_status": random.choice(["Single", "Married", "Divorced", "Widowed"]),
        "nationality": generator.country(),
        "email_address": generator.email(),
        "secondary_email_address": generator.email(),
        "phone_number": generator.phone_number(),
        "secondary_phone_number": generator.phone_number(),
        "street_address": generator.street_address(),
        "city": generator.city(),
        "state_province": generator.state(),
        "postal_code": generator.postcode(),
        "country": generator.country(),
        "passport_number": generator.bothify(text="P#########"),
        "drivers_license_number": generator.bothify(text="D########"),
        "health_insurance_number": generator.bothify(text="H#########"),
        "medical_record_number": generator.bothify(text="M#########"),
        "blood_type": random.choice(["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]),
        "allergies": generator.word(),
        "chronic_conditions": generator.word(),
        "medications": generator.word(),
        "job_title": generator.job(),
        "department": generator.word(),
        "employee_id": generator.bothify(text="E####"),
        "employer_name": generator.company(),
        "work_email_address": generator.email(),
        "student_id": generator.bothify(text="S####"),
        "university_college_name": generator.company(),
        "degree": random.choice(["BA", "BS", "MA", "MS", "PhD"]),
        "graduation_year": str(random.randint(1990, 2030)),
        "credit_card_number": generator.bothify(text="####-####-####-####"),
        "bank_account_number": generator.bothify(text="ACCT#########"),
        "iban": generator.bothify(text="??##########################")
    }


# ------------------ MYSQL/RDS/AURORA/POSTGRESQL INSERTION ------------------
def insert_data_mysql(num_rows, db_host, db_user, db_password, db_name):
    import mysql.connector
    import faker

    # Original lines for establishing Faker
    generator = faker.Faker()

    # Original line: # Connect to MySQL to check if database exists
    try:
        conn = mysql.connector.connect(host=db_host, user=db_user, password=db_password)
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES")
        databases = [db[0] for db in cursor.fetchall()]

        if db_name not in databases:
            create_db = input(
                f"The database '{db_name}' does not exist. Would you like to create it? (yes/no) [no]: ").strip().lower()
            if create_db == "yes":
                cursor.execute(f"CREATE DATABASE {db_name}")
            else:
                print("The specified database does not exist and cannot be created. Exiting.")
                sys.exit(1)

        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        sys.exit(1)

    # Original lines for connecting to the selected database
    try:
        conn = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db_name)
        cursor = conn.cursor()

        # Original line: # Create table if necessary
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS fake_data (
            first_name VARCHAR(50), middle_name VARCHAR(50), last_name VARCHAR(50), gender VARCHAR(20),
            date_of_birth DATE, marital_status VARCHAR(20), nationality VARCHAR(50), email_address VARCHAR(100),
            secondary_email_address VARCHAR(100), phone_number VARCHAR(20), secondary_phone_number VARCHAR(20),
            street_address VARCHAR(200), city VARCHAR(50), state_province VARCHAR(50), postal_code VARCHAR(20),
            country VARCHAR(50), passport_number VARCHAR(20), drivers_license_number VARCHAR(20),
            health_insurance_number VARCHAR(20), medical_record_number VARCHAR(20), blood_type VARCHAR(5),
            allergies VARCHAR(100), chronic_conditions VARCHAR(100), medications VARCHAR(100),
            job_title VARCHAR(100), department VARCHAR(50), employee_id VARCHAR(20), employer_name VARCHAR(100),
            work_email_address VARCHAR(100), student_id VARCHAR(20), university_college_name VARCHAR(100),
            degree VARCHAR(10), graduation_year INT, credit_card_number VARCHAR(20), bank_account_number VARCHAR(30),
            iban VARCHAR(34)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

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

        for _ in range(num_rows):
            record = generate_fake_record(generator)
            values = (
                record["first_name"], record["middle_name"], record["last_name"], record["gender"],
                record["date_of_birth"], record["marital_status"], record["nationality"],
                record["email_address"], record["secondary_email_address"], record["phone_number"],
                record["secondary_phone_number"], record["street_address"], record["city"],
                record["state_province"], record["postal_code"], record["country"], record["passport_number"],
                record["drivers_license_number"], record["health_insurance_number"], record["medical_record_number"],
                record["blood_type"], record["allergies"], record["chronic_conditions"], record["medications"],
                record["job_title"], record["department"], record["employee_id"], record["employer_name"],
                record["work_email_address"], record["student_id"], record["university_college_name"],
                record["degree"], record["graduation_year"], record["credit_card_number"],
                record["bank_account_number"], record["iban"]
            )
            cursor.execute(dml, values)

        conn.commit()
        print(f"{num_rows} rows inserted into fake_data table.")
    except mysql.connector.Error as err:
        print(f"Error inserting data: {err}")
    finally:
        cursor.close()
        conn.close()


# ------------------ DYNAMODB INSERTION ------------------
def insert_data_dynamodb(num_rows):
    import boto3
    import faker
    import maskpass
    from botocore.exceptions import ClientError

    print("DynamoDB selected. Please enter your AWS credentials.")
    aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
    aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
    region_name = input("Enter AWS region name [us-east-1]: ").strip() or "us-east-1"

    generator = faker.Faker()

    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )

    dynamodb = session.resource('dynamodb')
    client = session.client('dynamodb')

    table_name = input("Enter the DynamoDB table name [fake_data]: ").strip() or "fake_data"
    print(f"Using DynamoDB table: {table_name}")

    try:
        existing_tables = client.list_tables()['TableNames']
    except ClientError as e:
        print(f"Error listing DynamoDB tables: {e}")
        sys.exit(1)

    # If the table does not exist, ask the user if they'd like to create it
    if table_name not in existing_tables:
        print(f"The table '{table_name}' does not exist.")
        create_table = input(f"Would you like to create it? (yes/no) [yes]: ").strip().lower() or "yes"
        if create_table == "yes":
            try:
                print("Creating table. Please wait...")
                client.create_table(
                    TableName=table_name,
                    KeySchema=[
                        {'AttributeName': 'id', 'KeyType': 'HASH'}
                    ],
                    AttributeDefinitions=[
                        {'AttributeName': 'id', 'AttributeType': 'S'}
                    ],
                    ProvisionedThroughput={
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                )
                waiter = client.get_waiter('table_exists')
                waiter.wait(TableName=table_name)
                print(f"Table '{table_name}' created and is now active.")
            except ClientError as ce:
                print(f"Could not create the table '{table_name}': {ce}")
                sys.exit(1)
        else:
            print("The specified table does not exist and was not created. Exiting.")
            sys.exit(1)

    # At this point, the table exists and is active. We can proceed with data insertion.
    table = dynamodb.Table(table_name)
    try:
        for _ in range(num_rows):
            record = generate_fake_record(generator)
            item_data = {
                'id': str(random.randint(1000000, 9999999)),  # Primary key
                **record
            }
            table.put_item(Item=item_data)

        print(f"{num_rows} items inserted into DynamoDB table '{table_name}'.")
    except ClientError as e:
        print(f"Error inserting items into DynamoDB: {e}")
        sys.exit(1)


# ------------------ REDSHIFT INSERTION ------------------
def insert_data_redshift(num_rows):
    import psycopg2
    import faker

    generator = faker.Faker()

    print("Redshift selected. Please enter your Redshift credentials.")
    redshift_host = input("Enter Redshift endpoint: ").strip()
    redshift_port = input("Enter Redshift port [5439]: ").strip() or "5439"
    redshift_user = input("Enter Redshift user: ").strip()
    redshift_db = input("Enter Redshift database name: ").strip()
    redshift_password = maskpass.askpass(prompt="Enter Redshift password (input hidden): ", mask='*')

    try:
        conn = psycopg2.connect(
            dbname=redshift_db,
            user=redshift_user,
            password=redshift_password,
            host=redshift_host,
            port=redshift_port
        )
        cursor = conn.cursor()

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
        );
        """)

        dml = """
        INSERT INTO fake_data (
            first_name, middle_name, last_name, gender, date_of_birth, marital_status, nationality,
            email_address, secondary_email_address, phone_number, secondary_phone_number, street_address,
            city, state_province, postal_code, country, passport_number, drivers_license_number,
            health_insurance_number, medical_record_number, blood_type, allergies, chronic_conditions,
            medications, job_title, department, employee_id, employer_name, work_email_address,
            student_id, university_college_name, degree, graduation_year, credit_card_number,
            bank_account_number, iban
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        for _ in range(num_rows):
            record = generate_fake_record(generator)
            values = (
                record["first_name"], record["middle_name"], record["last_name"], record["gender"],
                record["date_of_birth"], record["marital_status"], record["nationality"],
                record["email_address"], record["secondary_email_address"], record["phone_number"],
                record["secondary_phone_number"], record["street_address"], record["city"], record["state_province"],
                record["postal_code"], record["country"], record["passport_number"], record["drivers_license_number"],
                record["health_insurance_number"], record["medical_record_number"], record["blood_type"],
                record["allergies"], record["chronic_conditions"], record["medications"], record["job_title"],
                record["department"], record["employee_id"], record["employer_name"], record["work_email_address"],
                record["student_id"], record["university_college_name"], record["degree"], record["graduation_year"],
                record["credit_card_number"], record["bank_account_number"], record["iban"]
            )
            cursor.execute(dml, values)

        conn.commit()
        print(f"{num_rows} rows inserted into Redshift fake_data table.")
    except Exception as e:
        print(f"Redshift insertion error: {e}")
    finally:
        cursor.close()
        conn.close()


# ------------------ S3 UPLOAD ------------------
def upload_data_s3(num_rows):
    import boto3
    import csv
    from io import StringIO
    import faker
    import maskpass
    from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

    print("S3 selected. Please enter your AWS credentials.")
    aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
    aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
    region_name = input("Enter AWS region name [us-east-1]: ").strip() or "us-east-1"

    s3_session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )

    s3 = s3_session.client('s3')
    bucket_name = input("Enter S3 bucket name: ").strip()
    object_name = input("Enter the S3 object name [fake_data.csv]: ").strip() or "fake_data.csv"

    generator = faker.Faker()

    # Generate CSV data
    output = StringIO()
    writer = csv.writer(output)
    header = [
        "first_name", "middle_name", "last_name", "gender", "date_of_birth", "marital_status",
        "nationality", "email_address", "secondary_email_address", "phone_number", "secondary_phone_number",
        "street_address", "city", "state_province", "postal_code", "country", "passport_number",
        "drivers_license_number", "health_insurance_number", "medical_record_number", "blood_type",
        "allergies", "chronic_conditions", "medications", "job_title", "department", "employee_id",
        "employer_name", "work_email_address", "student_id", "university_college_name", "degree",
        "graduation_year", "credit_card_number", "bank_account_number", "iban"
    ]
    writer.writerow(header)

    for _ in range(num_rows):
        record = generate_fake_record(generator)
        row = [
            record["first_name"], record["middle_name"], record["last_name"], record["gender"],
            record["date_of_birth"], record["marital_status"], record["nationality"],
            record["email_address"], record["secondary_email_address"], record["phone_number"],
            record["secondary_phone_number"], record["street_address"], record["city"],
            record["state_province"], record["postal_code"], record["country"], record["passport_number"],
            record["drivers_license_number"], record["health_insurance_number"], record["medical_record_number"],
            record["blood_type"], record["allergies"], record["chronic_conditions"], record["medications"],
            record["job_title"], record["department"], record["employee_id"], record["employer_name"],
            record["work_email_address"], record["student_id"], record["university_college_name"],
            record["degree"], record["graduation_year"], record["credit_card_number"],
            record["bank_account_number"], record["iban"]
        ]
        writer.writerow(row)

    data_bytes = output.getvalue().encode("utf-8")

    try:
        s3.put_object(Bucket=bucket_name, Key=object_name, Body=data_bytes)
        print(f"{num_rows} rows uploaded to s3://{bucket_name}/{object_name}")

    except NoCredentialsError:
        print("Error: No AWS credentials found. Please check your Access Key and Secret Key.")
    except PartialCredentialsError:
        print("Error: Incomplete AWS credentials. Please verify both Access Key and Secret Key.")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchBucket":
            print(f"Bucket '{bucket_name}' was not found. Please check the bucket name and try again.")
        elif error_code == "AccessDenied":
            print("Access was denied. Please verify your credentials and permissions for this bucket.")
        elif error_code == "InvalidAccessKeyId":
            print("The AWS Access Key ID you provided does not exist or is incorrect.")
        elif error_code == "SignatureDoesNotMatch":
            print("The request signature we calculated does not match the signature you provided. Check your Secret Key.")
        else:
            print(f"An unexpected S3 client error occurred: {e}")
    except Exception as e:
        print(f"An unknown error occurred during S3 upload: {e}")


# ------------------ MAIN SCRIPT LOGIC (preserves original argument usage) ------------------
parser = argparse.ArgumentParser(description="Generate and insert fake data into various services.")
parser.add_argument("--num_rows", type=int, help="Number of rows to insert (1-500)")
parser.add_argument("--db_host", type=str, help="Database host")
parser.add_argument("--db_user", type=str, help="Database user")
parser.add_argument("--db_name", type=str, help="Database name")
parser.add_argument("--service", type=str, required=True,
                    help="Service to insert data into: mysql/mariadb/aurora/postgresql/rds/dynamodb/redshift/s3")
args = parser.parse_args()

# Original line for collecting parameters, showing defaults if provided
num_rows = args.num_rows if args.num_rows else int(input("Enter the number of rows to insert (1-500) [100]: ") or 100)

# We do not assume any default service now; the user must choose via --service
service_choice = args.service.lower().strip()

# The user should be prompted only for the credentials relevant to the selected service:
# MySQL / Aurora / RDS / MariaDB / PostgreSQL block
if service_choice in ["mysql", "mariadb", "aurora", "rds", "postgresql"]:
    db_host = args.db_host if args.db_host else input("Enter the database host [localhost]: ") or "localhost"
    db_user = args.db_user if args.db_user else input("Enter the database user [root]: ") or "root"
    db_password = maskpass.askpass(prompt="Enter the database password (input hidden): ", mask='*')
    db_name = args.db_name if args.db_name else input("Enter the database name [test_db]: ") or "test_db"
    insert_data_mysql(num_rows, db_host, db_user, db_password, db_name)

elif service_choice == "dynamodb":
    insert_data_dynamodb(num_rows)

elif service_choice == "redshift":
    insert_data_redshift(num_rows)

elif service_choice == "s3":
    upload_data_s3(num_rows)

else:
    print("Unknown or unsupported service choice. Exiting.")
    sys.exit(1)
