import subprocess
import sys
import argparse
import random
import os
import json
import time
import string

RESOURCES_FILE = "resources_created.json"

def is_package_installed(package):
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "show", package],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

def check_and_install_dependencies():
    required_packages = [
        "mysql-connector-python",
        "faker",
        "psycopg2-binary",
        "boto3",
        "maskpass",
        "botocore",
        "requests"
    ]
    missing_packages = [pkg for pkg in required_packages if not is_package_installed(pkg)]

    if missing_packages:
        print(f"The following dependencies are missing: {', '.join(missing_packages)}")
        install = input("Would you like to install them? (yes/no) [yes]: ").strip().lower() or "yes"
        if install == "yes":
            for package in missing_packages:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", package],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            print("Dependencies installed successfully.")
        else:
            print("Missing dependencies were not installed. The script may not run correctly.")
            sys.exit(1)

check_and_install_dependencies()

import maskpass
import faker
import requests
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

def load_resources_file() -> dict:
    """
    Loads the resources_created dictionary from RESOURCES_FILE if it exists,
    otherwise returns an empty dict.
    """
    if os.path.exists(RESOURCES_FILE):
        try:
            with open(RESOURCES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}

def save_resources_file(resources: dict):
    """
    Saves the resources_created dictionary to RESOURCES_FILE as JSON.
    """
    try:
        with open(RESOURCES_FILE, "w", encoding="utf-8") as f:
            json.dump(resources, f, indent=2)
    except OSError as e:
        print(f"Error writing to {RESOURCES_FILE}: {e}")

def show_loading(message="Working", wait_seconds=3):
    """
    Displays a basic loading message for 'wait_seconds'.
    """
    print(f"\n{message}...")
    for _ in range(wait_seconds):
        time.sleep(1)
        print(".", end="", flush=True)
    print("\n")

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

###############################################################################
# Insert data into Redshift function
###############################################################################
def insert_data_redshift(num_rows, aws_access_key_id=None, aws_secret_access_key=None, region_name=None):
    import psycopg2
    import boto3
    import random
    import string
    import time

    resources = load_resources_file()

    # If no credentials or region, prompt
    if not aws_access_key_id:
        aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
    if not aws_secret_access_key:
        aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
    if not region_name:
        region_name = input("Enter AWS region name [us-east-1]: ").strip() or "us-east-1"

    # Prompt for cluster creation details
    cluster_identifier = input("Enter Redshift cluster identifier [my-demo-redshift]: ").strip() or "my-demo-redshift"
    node_type = input("Enter Redshift node type [dc2.large]: ").strip() or "dc2.large"
    num_nodes_str = input("Enter number of nodes [2]: ").strip() or "2"
    try:
        number_of_nodes = int(num_nodes_str)
    except ValueError:
        number_of_nodes = 2

    db_name = input("Enter Redshift database name [dev]: ").strip() or "dev"

    # Check if we already stored a user/pwd for this cluster in resources
    existing_cluster_data = None
    if "resources" in resources:
        for res in resources["resources"]:
            if res.get("type") == "redshift_cluster" and res.get("cluster_identifier") == cluster_identifier:
                existing_cluster_data = res
                break

    if existing_cluster_data:
        # We already have a master_username and possibly password
        print(f"Found existing cluster data for '{cluster_identifier}' in resources file.")
        user_provided_username = existing_cluster_data["master_username"]
        # If we have the password, re-use it; if not, user must provide
        if "master_password" in existing_cluster_data and existing_cluster_data["master_password"]:
            user_provided_password = existing_cluster_data["master_password"]
            print("Re-using stored master password from resources file.")
        else:
            user_provided_password = maskpass.askpass(
                prompt="Enter Redshift master password (input hidden): ",
                mask='*'
            )
    else:
        # If user doesn't provide a username/password, random ones get generated
        user_provided_username = input("Enter Redshift master username (leave blank to autogenerate): ").strip() or None
        user_provided_password = maskpass.askpass(
            prompt="Enter Redshift master password (input hidden) or leave blank to autogenerate: ",
            mask='*'
        ) or None

    # Ask user for NAT CIDR
    nat_cidr = input("Enter your NAT/public IP in CIDR format (e.g. 1.2.3.4/32) or leave blank to auto-detect: ").strip()
    if not nat_cidr:
        print("No IP entered; fetching your public IP address from checkip.amazonaws.com...")
        try:
            import requests
            my_ip = requests.get("https://checkip.amazonaws.com").text.strip()
            nat_cidr = f"{my_ip}/32"
            print(f"Using your detected IP: {nat_cidr}")
        except Exception as e:
            print(f"Error automatically fetching public IP address: {e}")
            print("Cannot proceed without an IP. Please try again or specify your NAT CIDR manually.")
            return

    redshift_client = boto3.client(
        "redshift",
        region_name=region_name,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )
    ec2 = boto3.client(
        "ec2",
        region_name=region_name,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    # 1) Figure out which VPC we'll use - pick default or prompt
    try:
        response = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        if response["Vpcs"]:
            default_vpc_id = response["Vpcs"][0]["VpcId"]
            print(f"Found default VPC: {default_vpc_id}")
        else:
            default_vpc_id = input("Could not find default VPC. Please enter a VPC ID: ").strip()
    except Exception as e:
        print(f"Error describing VPCs: {e}")
        return

    # 2) Create (or find) a security group for inbound on port 5439 from NAT IP
    sg_name = "MyRedshiftInboundSG"
    sg_id = None
    from botocore.exceptions import ClientError
    try:
        existing_sg = ec2.describe_security_groups(Filters=[
            {"Name": "group-name", "Values": [sg_name]},
            {"Name": "vpc-id", "Values": [default_vpc_id]}
        ])
        if existing_sg["SecurityGroups"]:
            sg_id = existing_sg["SecurityGroups"][0]["GroupId"]
            print(f"Security group '{sg_name}' already exists with ID '{sg_id}'. Reusing it.")
        else:
            print(f"Creating security group '{sg_name}' in VPC '{default_vpc_id}'...")
            create_resp = ec2.create_security_group(
                GroupName=sg_name,
                Description="Security group for Redshift inbound from my NAT IP",
                VpcId=default_vpc_id
            )
            sg_id = create_resp["GroupId"]
            print(f"Created security group with ID '{sg_id}'.")
    except ClientError as e:
        print(f"Error checking/creating security group: {e}")
        return

    try:
        print(f"Authorizing inbound for port 5439 from {nat_cidr} on SG {sg_id}...")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5439,
                    "ToPort": 5439,
                    "IpRanges": [{"CidrIp": nat_cidr, "Description": "Redshift inbound"}]
                }
            ]
        )
        print("Security group inbound rule set.")
    except ClientError as e:
        if "InvalidPermission.Duplicate" in str(e):
            print("Inbound rule already exists. Proceeding.")
        else:
            print(f"Error authorizing inbound rule: {e}")

    # 3) Create or reuse the cluster
    cluster_exists = False
    try:
        existing_desc = redshift_client.describe_clusters(ClusterIdentifier=cluster_identifier)
        if existing_desc["Clusters"]:
            print(f"Cluster '{cluster_identifier}' already exists. Not creating a new one.")
            cluster_exists = True
    except ClientError as e:
        if "ClusterNotFound" in str(e):
            # Need to create it
            print(f"Creating Redshift cluster '{cluster_identifier}'...")
            if not user_provided_username:
                user_provided_username = "user_" + "".join(random.choices(string.ascii_lowercase, k=6))
            if not user_provided_password:
                user_provided_password = "Passw0rd_" + "".join(random.choices(string.ascii_letters + string.digits, k=8))

            try:
                redshift_client.create_cluster(
                    ClusterIdentifier=cluster_identifier,
                    NodeType=node_type,
                    NumberOfNodes=number_of_nodes,
                    DBName=db_name,
                    MasterUsername=user_provided_username,
                    MasterUserPassword=user_provided_password,
                    PubliclyAccessible=True,
                    VpcSecurityGroupIds=[sg_id]
                )
                print("Cluster creation initiated. Waiting for cluster to become available...")
                cluster_status = "creating"
                while cluster_status != "available":
                    time.sleep(30)
                    desc = redshift_client.describe_clusters(ClusterIdentifier=cluster_identifier)
                    cluster_status = desc["Clusters"][0]["ClusterStatus"]
                    print(f"Current cluster status: {cluster_status} (waiting for 'available')")

                print(f"Cluster '{cluster_identifier}' is now available.")
            except Exception as ce:
                print(f"Error creating Redshift cluster '{cluster_identifier}': {ce}")
                return
        else:
            print(f"Unexpected error describing cluster: {e}")
            return

    # 4) Gather final connection info
    desc = redshift_client.describe_clusters(ClusterIdentifier=cluster_identifier)
    cluster_info = desc["Clusters"][0]
    host = cluster_info["Endpoint"]["Address"]
    port = cluster_info["Endpoint"]["Port"]
    final_db_name = cluster_info.get("DBName", db_name)

    # If cluster existed, it might have a different username than we attempted
    final_master_username = cluster_info.get("MasterUsername", user_provided_username or "admin")
    # If the resource was in the file, we re-use that password. If not, we prompt or use what we generated
    if existing_cluster_data and "master_password" in existing_cluster_data:
        final_master_password = existing_cluster_data["master_password"]
    else:
        final_master_password = user_provided_password or maskpass.askpass(
            prompt="Enter Redshift master password (input hidden): ",
            mask='*'
        )

    show_loading("Establishing Redshift connection", 2)
    generator = faker.Faker()
    schema_name = "fake_schema"
    try:
        conn = psycopg2.connect(
            dbname=final_db_name,
            user=final_master_username,
            password=final_master_password,
            host=host,
            port=port
        )
        cursor = conn.cursor()

        # Create schema
        cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name};")

        # Create table
        cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {schema_name}.fake_data (
            first_name VARCHAR(50),
            middle_name VARCHAR(50),
            last_name VARCHAR(50),
            gender VARCHAR(70),
            date_of_birth DATE,
            marital_status VARCHAR(70),
            nationality VARCHAR(50),
            email_address VARCHAR(100),
            secondary_email_address VARCHAR(100),
            phone_number VARCHAR(70),
            secondary_phone_number VARCHAR(70),
            street_address VARCHAR(200),
            city VARCHAR(50),
            state_province VARCHAR(50),
            postal_code VARCHAR(70),
            country VARCHAR(50),
            passport_number VARCHAR(70),
            drivers_license_number VARCHAR(70),
            health_insurance_number VARCHAR(70),
            medical_record_number VARCHAR(70),
            blood_type VARCHAR(5),
            allergies VARCHAR(100),
            chronic_conditions VARCHAR(100),
            medications VARCHAR(100),
            job_title VARCHAR(100),
            department VARCHAR(50),
            employee_id VARCHAR(70),
            employer_name VARCHAR(100),
            work_email_address VARCHAR(100),
            student_id VARCHAR(70),
            university_college_name VARCHAR(100),
            degree VARCHAR(10),
            graduation_year INT,
            credit_card_number VARCHAR(70),
            bank_account_number VARCHAR(30),
            iban VARCHAR(34)
        );
        """)

        show_loading("Inserting data into Redshift", 2)

        # 36 columns => 36 placeholders
        dml = f"""
        INSERT INTO {schema_name}.fake_data (
            first_name, middle_name, last_name, gender, date_of_birth, marital_status, nationality,
            email_address, secondary_email_address, phone_number, secondary_phone_number, street_address,
            city, state_province, postal_code, country, passport_number, drivers_license_number,
            health_insurance_number, medical_record_number, blood_type, allergies, chronic_conditions,
            medications, job_title, department, employee_id, employer_name, work_email_address,
            student_id, university_college_name, degree, graduation_year, credit_card_number,
            bank_account_number, iban
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
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
        print(f"{num_rows} rows inserted into Redshift table '{schema_name}.fake_data'.")

        # Save info (or update if we already have entry) in resources_created.json
        resources_entry = None
        if "resources" not in resources:
            resources["resources"] = []

        # Check if we already have an entry for this cluster
        for res in resources["resources"]:
            if res.get("type") == "redshift_cluster" and res.get("cluster_identifier") == cluster_identifier:
                resources_entry = res
                break

        if not resources_entry:
            resources_entry = {
                "type": "redshift_cluster",
                "cluster_identifier": cluster_identifier,
                "host": host,
                "port": port,
                "database": final_db_name,
                "schema": schema_name,
                "table": "fake_data",
                "security_group": sg_id,
                "nat_cidr": nat_cidr
            }
            resources["resources"].append(resources_entry)

        # Always update username, password
        resources_entry["master_username"] = final_master_username
        resources_entry["master_password"] = final_master_password

        save_resources_file(resources)

    except Exception as e:
        print(f"Redshift insertion error: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


def insert_data_mysql(num_rows, db_host, db_user, db_password, db_name):
    import mysql.connector
    generator = faker.Faker()
    resources = load_resources_file()

    show_loading("Establishing MySQL connection", 2)

    try:
        conn = mysql.connector.connect(host=db_host, user=db_user, password=db_password)
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES")
        databases = [db[0] for db in cursor.fetchall()]

        if db_name not in databases:
            create_db = input(
                f"The database '{db_name}' does not exist. Create it? (yes/no) [no]: "
            ).strip().lower()
            if create_db == "yes":
                cursor.execute(f"CREATE DATABASE {db_name}")
                print(f"Database '{db_name}' created.")
            else:
                print("The specified database does not exist and cannot be created. Exiting.")
                sys.exit(1)

        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        sys.exit(1)

    show_loading("Inserting data into MySQL", 2)

    try:
        conn = mysql.connector.connect(
            host=db_host, user=db_user, password=db_password, database=db_name
        )
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS fake_data (
            first_name VARCHAR(50), middle_name VARCHAR(50), last_name VARCHAR(50), gender VARCHAR(70),
            date_of_birth DATE, marital_status VARCHAR(70), nationality VARCHAR(50), email_address VARCHAR(100),
            secondary_email_address VARCHAR(100), phone_number VARCHAR(70), secondary_phone_number VARCHAR(70),
            street_address VARCHAR(200), city VARCHAR(50), state_province VARCHAR(50), postal_code VARCHAR(70),
            country VARCHAR(50), passport_number VARCHAR(70), drivers_license_number VARCHAR(70),
            health_insurance_number VARCHAR(70), medical_record_number VARCHAR(70), blood_type VARCHAR(5),
            allergies VARCHAR(100), chronic_conditions VARCHAR(100), medications VARCHAR(100),
            job_title VARCHAR(100), department VARCHAR(50), employee_id VARCHAR(70), employer_name VARCHAR(100),
            work_email_address VARCHAR(100), student_id VARCHAR(70), university_college_name VARCHAR(100),
            degree VARCHAR(10), graduation_year INT, credit_card_number VARCHAR(70), bank_account_number VARCHAR(30),
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
        print(f"{num_rows} rows inserted into MySQL table 'fake_data'.")
        mysql_entry = {
            "type": "mysql",
            "db_host": db_host,
            "db_name": db_name,
            "table": "fake_data"
        }
        if "resources" not in resources:
            resources["resources"] = []
        resources["resources"].append(mysql_entry)
        save_resources_file(resources)

    except mysql.connector.Error as err:
        print(f"Error inserting data: {err}")
    finally:
        cursor.close()
        conn.close()

def insert_data_dynamodb(num_rows, aws_access_key_id=None, aws_secret_access_key=None, region_name=None):
    import boto3
    resources = load_resources_file()

    if not aws_access_key_id:
        aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
    if not aws_secret_access_key:
        aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
    if not region_name:
        region_name = input("Enter AWS region name [us-east-1]: ").strip() or "us-east-1"

    generator = faker.Faker()
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )

    client = session.client('dynamodb')
    dynamodb = session.resource('dynamodb')

    table_name = input("Enter the DynamoDB table name [fake_data]: ").strip() or "fake_data"
    print(f"Using DynamoDB table: {table_name}")

    show_loading("Checking DynamoDB table existence", 2)

    try:
        existing_tables = client.list_tables()['TableNames']
    except ClientError as e:
        print(f"Error listing DynamoDB tables: {e}")
        sys.exit(1)

    if table_name not in existing_tables:
        print(f"The table '{table_name}' does not exist.")
        create_table = input("Create it? (yes/no) [yes]: ").strip().lower() or "yes"
        if create_table == "yes":
            try:
                print("Creating table. Please wait...")
                client.create_table(
                    TableName=table_name,
                    KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
                    AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
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

    show_loading("Inserting items into DynamoDB", 2)

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
        ddb_entry = {
            "type": "dynamodb",
            "region": region_name,
            "table_name": table_name
        }
        if "resources" not in resources:
            resources["resources"] = []
        resources["resources"].append(ddb_entry)
        save_resources_file(resources)

    except ClientError as e:
        print(f"Error inserting items into DynamoDB: {e}")
        sys.exit(1)

def upload_data_s3(num_rows, aws_access_key_id=None, aws_secret_access_key=None, region_name=None):
    import boto3
    import csv
    from io import StringIO

    resources = load_resources_file()

    if not aws_access_key_id:
        aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
    if not aws_secret_access_key:
        aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
    if not region_name:
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

    show_loading("Generating CSV for S3", 2)

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

    show_loading(f"Uploading CSV to s3://{bucket_name}/{object_name}", 2)

    try:
        s3.put_object(Bucket=bucket_name, Key=object_name, Body=data_bytes)
        print(f"{num_rows} rows uploaded to s3://{bucket_name}/{object_name}")
        s3_entry = {
            "type": "s3",
            "bucket": bucket_name,
            "object_key": object_name,
            "region": region_name
        }
        if "resources" not in resources:
            resources["resources"] = []
        resources["resources"].append(s3_entry)
        save_resources_file(resources)

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
            print("The request signature does not match. Check your Secret Key.")
        else:
            print(f"An unexpected S3 client error occurred: {e}")
    except Exception as e:
        print(f"An unknown error occurred during S3 upload: {e}")

def cleanup_resources():
    """
    Reads from resources_created.json, attempts to delete all resources that the script created,
    including Redshift clusters, MySQL data, DynamoDB tables, and S3 uploads.
    """
    import boto3
    import psycopg2
    import mysql.connector

    if not os.path.exists(RESOURCES_FILE):
        print("\nNo resources file found; nothing to clean up.")
        return

    try:
        with open(RESOURCES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Could not read {RESOURCES_FILE}: {e}")
        return

    if "resources" not in data or not data["resources"]:
        print("\nNo resources recorded; nothing to clean up.")
        return

    print("\nCleaning up / Destroying resources created by this script...")
    for resource in data["resources"]:
        rtype = resource.get("type", "")
        if rtype == "mysql":
            import mysql.connector
            print(f"\nDropping MySQL table '{resource['table']}' in DB '{resource['db_name']}' on host '{resource['db_host']}'...")
            db_host = resource["db_host"]
            db_name = resource["db_name"]
            table = resource["table"]
            db_user = input("Enter MySQL user [root]: ") or "root"
            db_password = maskpass.askpass(prompt="Enter MySQL password (input hidden): ", mask='*')
            try:
                conn = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db_name)
                cursor = conn.cursor()
                cursor.execute(f"DROP TABLE IF EXISTS {table}")
                conn.commit()
                print(f"Table '{table}' dropped.")
            except mysql.connector.Error as err:
                print(f"MySQL table drop error: {err}")
            finally:
                if 'cursor' in locals():
                    cursor.close()
                if 'conn' in locals() and conn.is_connected():
                    conn.close()

        elif rtype == "dynamodb":
            import boto3
            aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
            aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=resource["region"]
            )
            ddb_client = session.client('dynamodb')
            try:
                print(f"\nDeleting DynamoDB table '{resource['table_name']}' in region '{resource['region']}'...")
                ddb_client.delete_table(TableName=resource["table_name"])
                waiter = ddb_client.get_waiter('table_not_exists')
                waiter.wait(TableName=resource["table_name"])
                print(f"Table '{resource['table_name']}' deleted.")
            except ClientError as e:
                print(f"Error deleting DynamoDB table '{resource['table_name']}': {e}")

        elif rtype == "redshift":
            # older "redshift" type logic, if any
            print(f"\nDropping Redshift table '{resource['table']}' in database '{resource['database']}' on '{resource['host']}:{resource['port']}'...")
            user = input("Enter Redshift user: ").strip()
            password = maskpass.askpass(prompt="Enter Redshift password (input hidden): ", mask='*')
            try:
                conn = psycopg2.connect(
                    dbname=resource["database"],
                    user=user,
                    password=password,
                    host=resource["host"],
                    port=resource["port"]
                )
                cursor = conn.cursor()
                cursor.execute(f"DROP TABLE IF EXISTS {resource['table']}")
                conn.commit()
                print(f"Redshift table '{resource['table']}' dropped.")
            except Exception as e:
                print(f"Could not drop Redshift table '{resource['table']}': {e}")
            finally:
                if 'cursor' in locals():
                    cursor.close()
                if 'conn' in locals():
                    conn.close()

        elif rtype == "redshift_cluster":
            # Properly drop table & schema, then delete the entire cluster
            print(f"\nDropping Redshift cluster '{resource['cluster_identifier']}' and all data.")
            import psycopg2

            user = resource["master_username"]
            host = resource["host"]
            port = resource["port"]
            db_name = resource["database"]
            schema = resource["schema"]
            table = resource["table"]

            # Use stored master password if we have it, otherwise prompt
            if "master_password" in resource and resource["master_password"]:
                password = resource["master_password"]
                print("Using stored master password from resources file.")
            else:
                password = maskpass.askpass(
                    prompt=f"Enter master password for Redshift cluster '{resource['cluster_identifier']}' (input hidden): ",
                    mask='*'
                )

            try:
                conn = psycopg2.connect(dbname=db_name, user=user, password=password, host=host, port=port)
                cursor = conn.cursor()
                # Drop the table
                cursor.execute(f"DROP TABLE IF EXISTS {schema}.{table}")
                # Optionally drop the schema
                cursor.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
                conn.commit()
                print(f"Dropped table '{schema}.{table}' and schema '{schema}'.")
            except Exception as e:
                print(f"Could not drop Redshift table/schema: {e}")
            finally:
                if 'cursor' in locals():
                    cursor.close()
                if 'conn' in locals():
                    conn.close()

            # Now delete the cluster
            region = resource.get("region", "us-east-1")  # or store region if needed
            # Prompt or use stored AWS creds (choose to prompt for safety)
            aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
            aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
            redshift_client = boto3.client(
                "redshift",
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            try:
                print(f"Deleting cluster '{resource['cluster_identifier']}' (this may take a few minutes)...")
                redshift_client.delete_cluster(
                    ClusterIdentifier=resource["cluster_identifier"],
                    SkipFinalClusterSnapshot=True
                )
                waiter = redshift_client.get_waiter("cluster_deleted")
                waiter.wait(ClusterIdentifier=resource["cluster_identifier"])
                print(f"Cluster '{resource['cluster_identifier']}' has been deleted.")
            except Exception as e:
                print(f"Could not delete Redshift cluster '{resource['cluster_identifier']}': {e}")

        elif rtype == "s3":
            print(f"\nDeleting S3 object '{resource['object_key']}' from bucket '{resource['bucket']}' in region '{resource['region']}'...")
            import boto3
            aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
            aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
            s3_session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=resource["region"]
            )
            s3_client = s3_session.client('s3')
            try:
                s3_client.delete_object(Bucket=resource["bucket"], Key=resource["object_key"])
                print(f"S3 object '{resource['object_key']}' deleted.")
            except ClientError as e:
                print(f"Could not delete S3 object '{resource['object_key']}': {e}")

        else:
            print(f"\nUnknown resource type: {rtype}. Skipping.")

    print("\nCleanup complete. You can now safely remove the resources file if desired.")

def main():
    parser = argparse.ArgumentParser(
        description="Generate and insert fake data into various services, or cleanup existing resources."
    )
    parser.add_argument("--cleanup", action="store_true",
                        help="If set, script only runs cleanup for previously created resources, ignoring other arguments.")

    # If not doing cleanup, the user may supply service/rows as normal
    parser.add_argument("--service", type=str,
                        help="Comma-separated list of services or 'all'. Options: mysql, mariadb, aurora, postgresql, rds, dynamodb, redshift, s3, all.")
    parser.add_argument("--num_rows", type=int, help="Number of rows to insert (1-500)")
    parser.add_argument("--db_host", type=str, help="Database host")
    parser.add_argument("--db_user", type=str, help="Database user")
    parser.add_argument("--db_name", type=str, help="Database name")

    parser.add_argument("--aws_access_key_id", type=str, help="AWS Access Key ID")
    parser.add_argument("--aws_secret_access_key", type=str, help="AWS Secret Access Key")
    parser.add_argument("--aws_region", type=str, help="AWS region")

    args = parser.parse_args()

    # If cleanup is requested, skip everything else
    if args.cleanup:
        cleanup_resources()
        sys.exit(0)

    valid_services = ["mysql", "mariadb", "aurora", "postgresql", "rds", "dynamodb", "redshift", "s3"]
    if not args.service:
        print("Error: --service is required unless you specify --cleanup.")
        print(f"Valid services: {', '.join(valid_services)}")
        sys.exit(1)

    requested_services = [svc.strip().lower() for svc in args.service.split(",")]
    if "all" in requested_services:
        requested_services = valid_services

    # Validate all the services
    for svc in requested_services:
        if svc not in valid_services:
            print(f"Error: Unknown or unsupported service '{svc}'.")
            print(f"Valid services: {', '.join(valid_services)}")
            sys.exit(1)

    # Determine the number of rows
    if args.num_rows:
        num_rows = args.num_rows
    else:
        num_rows = int(input("Enter the number of rows to insert (1-500) [100]: ") or 100)

    print(f"All resources created will be recorded in '{RESOURCES_FILE}'. Do not delete it if you plan to run cleanup.\n")

    # Process each service
    for svc in requested_services:
        if svc in ["mysql", "mariadb", "aurora", "postgresql", "rds"]:
            db_host = args.db_host if args.db_host else input("Enter the database host [localhost]: ") or "localhost"
            db_user = args.db_user if args.db_user else input("Enter the database user [root]: ") or "root"
            db_password = maskpass.askpass(prompt="Enter the database password (input hidden): ", mask='*')
            db_name = args.db_name if args.db_name else input("Enter the database name [test_db]: ") or "test_db"
            insert_data_mysql(num_rows, db_host, db_user, db_password, db_name)

        elif svc == "dynamodb":
            insert_data_dynamodb(
                num_rows,
                aws_access_key_id=args.aws_access_key_id,
                aws_secret_access_key=args.aws_secret_access_key,
                region_name=args.aws_region
            )

        elif svc == "redshift":
            insert_data_redshift(
                num_rows,
                aws_access_key_id=args.aws_access_key_id,
                aws_secret_access_key=args.aws_secret_access_key,
                region_name=args.aws_region
            )

        elif svc == "s3":
            upload_data_s3(
                num_rows,
                aws_access_key_id=args.aws_access_key_id,
                aws_secret_access_key=args.aws_secret_access_key,
                region_name=args.aws_region
            )


if __name__ == "__main__":
    main()
