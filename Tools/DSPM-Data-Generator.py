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


def insert_data_aws_mysql(num_rows, aws_access_key_id=None, aws_secret_access_key=None, region_name=None):
    """
    Creates or reuses an AWS RDS MySQL instance, authorizes inbound from your NAT IP,
    waits for the DB to be available, connects, creates the 'fake_data' table,
    inserts synthetic rows, and logs it in resources_created.json.
    """
    import boto3
    import mysql.connector
    import random
    import string
    import time
    from botocore.exceptions import ClientError

    # We'll import the existing load/save helpers and "faker"
    resources = load_resources_file()
    generator = faker.Faker()

    if not aws_access_key_id:
        aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (hidden): ", mask='*')
    if not aws_secret_access_key:
        aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (hidden): ", mask='*')
    if not region_name:
        region_name = input("Enter AWS region name [us-east-1]: ").strip() or "us-east-1"

    rds_client = boto3.client(
        "rds",
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

    # 1) Ask user for DB instance ID
    db_instance_id = input("Enter RDS MySQL DBInstanceIdentifier [DSPM-Data-Gen-MySQL]: ").strip() or "DSPM-Data-Gen-MySQL"

    # 2) Possibly re-use credentials from resources file if we already have an entry
    existing_rds_entry = None
    if "resources" in resources:
        for r in resources["resources"]:
            if r.get("type") == "rds_instance" and r.get("db_instance_id") == db_instance_id:
                existing_rds_entry = r
                break

    if existing_rds_entry:
        print(f"Found existing RDS instance in resources file for '{db_instance_id}'. Re-using credentials.")
        master_username = existing_rds_entry.get("master_username", "admin")
        master_password = existing_rds_entry.get("master_password", "")
    else:
        # If user doesn't supply them, generate random
        master_username = input("Enter RDS MySQL master username (leave blank to auto-generate): ").strip()
        if not master_username:
            master_username = "admin"
        user_provided_password = maskpass.askpass(prompt="Enter RDS MySQL master password (hidden) or leave blank to auto-generate: ", mask='*')
        if user_provided_password:
            master_password = user_provided_password
        else:
            # random pass
            master_password = "Passw0rd_" + "".join(random.choices(string.ascii_letters + string.digits, k=8))

    # 3) NAT CIDR for inbound
    nat_cidr = input("Enter your NAT/public IP in CIDR notation (e.g. 1.2.3.4/32) or leave blank to auto-detect: ").strip()
    if not nat_cidr:
        print("No IP given, fetching from https://checkip.amazonaws.com ...")
        try:
            import requests
            my_ip = requests.get("https://checkip.amazonaws.com").text.strip()
            nat_cidr = f"{my_ip}/32"
            print(f"Using detected IP: {nat_cidr}")
        except Exception as e:
            print(f"Could not fetch your IP automatically: {e}")
            return

    # 4) Create or reuse a security group allowing inbound MySQL (port 3306)
    try:
        response = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        if response["Vpcs"]:
            default_vpc_id = response["Vpcs"][0]["VpcId"]
            print(f"Found default VPC: {default_vpc_id}")
        else:
            default_vpc_id = input("No default VPC. Please enter a VPC ID: ").strip()
    except Exception as e:
        print(f"Error describing VPCs: {e}")
        return

    sg_name = "MyMySQLInboundSG"
    sg_id = None

    try:
        sg_desc = ec2.describe_security_groups(Filters=[
            {"Name": "group-name", "Values": [sg_name]},
            {"Name": "vpc-id", "Values": [default_vpc_id]}
        ])
        if sg_desc["SecurityGroups"]:
            sg_id = sg_desc["SecurityGroups"][0]["GroupId"]
            print(f"Security group '{sg_name}' already exists (ID '{sg_id}'). Reusing it.")
        else:
            print(f"Creating security group '{sg_name}' in VPC '{default_vpc_id}'...")
            create_resp = ec2.create_security_group(
                GroupName=sg_name,
                Description="Allow inbound MySQL from NAT IP",
                VpcId=default_vpc_id
            )
            sg_id = create_resp["GroupId"]
            print(f"Created security group with ID '{sg_id}'.")
    except ClientError as e:
        print(f"Error creating/finding security group: {e}")
        return

    # Authorize inbound on 3306
    try:
        print(f"Authorizing inbound on port 3306 from {nat_cidr} in SG {sg_id}...")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpRanges": [{"CidrIp": nat_cidr, "Description": "MySQL inbound"}]
                }
            ]
        )
        print("Inbound rule set.")
    except ClientError as e:
        if "InvalidPermission.Duplicate" in str(e):
            print("Inbound rule already exists, continuing.")
        else:
            print(f"Error authorizing inbound rule: {e}")

    # 5) Check if DB instance exists
    instance_exists = False
    try:
        desc = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        if desc and desc["DBInstances"]:
            instance_exists = True
            print(f"RDS instance '{db_instance_id}' already exists; not creating new.")
    except ClientError as e:
        if "DBInstanceNotFound" in str(e):
            # Need to create
            print(f"Creating RDS MySQL instance '{db_instance_id}' with master user '{master_username}' ...")
            try:
                rds_client.create_db_instance(
                    DBInstanceIdentifier=db_instance_id,
                    AllocatedStorage=5,
                    DBName="test_db",  # initial DB to create
                    Engine="mysql",
                    DBInstanceClass="db.t3.micro",
                    PubliclyAccessible=True,
                    VpcSecurityGroupIds=[sg_id],
                    MasterUsername=master_username,
                    MasterUserPassword=master_password,
                    BackupRetentionPeriod=0,  # effectively disables backups
                    StorageType="gp2"
                )
                print("RDS MySQL creation initiated. Waiting for 'available' status...")
                status = "creating"
                while status != "available":
                    time.sleep(30)
                    d = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
                    status = d["DBInstances"][0]["DBInstanceStatus"]
                    print(f"Status: {status} (waiting for 'available')")

                print(f"RDS MySQL instance '{db_instance_id}' is now available.")
            except Exception as ce:
                print(f"Error creating MySQL instance: {ce}")
                return
        else:
            print(f"Error describing DB instance: {e}")
            return

    # 6) Retrieve the endpoint, port
    desc2 = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
    db_info = desc2["DBInstances"][0]
    endpoint = db_info["Endpoint"]["Address"]
    port = db_info["Endpoint"]["Port"]

    # We'll create or reuse the final DB name "test_db" for the data
    final_db_name = "test_db"

    # 7) Insert data
    show_loading(f"Connecting to MySQL at {endpoint}:{port} / DB: {final_db_name}", 4)

    try:
        # Connect to the main DB
        conn = mysql.connector.connect(
            host=endpoint,
            user=master_username,
            password=master_password,
            database=final_db_name,
            port=port
        )
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS fake_data (
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
            rec = generate_fake_record(generator)
            values = (
                rec["first_name"], rec["middle_name"], rec["last_name"], rec["gender"],
                rec["date_of_birth"], rec["marital_status"], rec["nationality"],
                rec["email_address"], rec["secondary_email_address"], rec["phone_number"],
                rec["secondary_phone_number"], rec["street_address"], rec["city"],
                rec["state_province"], rec["postal_code"], rec["country"], rec["passport_number"],
                rec["drivers_license_number"], rec["health_insurance_number"], rec["medical_record_number"],
                rec["blood_type"], rec["allergies"], rec["chronic_conditions"], rec["medications"],
                rec["job_title"], rec["department"], rec["employee_id"], rec["employer_name"],
                rec["work_email_address"], rec["student_id"], rec["university_college_name"],
                rec["degree"], rec["graduation_year"], rec["credit_card_number"],
                rec["bank_account_number"], rec["iban"]
            )
            cursor.execute(dml, values)

        conn.commit()
        print(f"{num_rows} rows inserted into RDS MySQL table 'fake_data' in DB '{final_db_name}'.")
    except Exception as e:
        print(f"Error inserting data into RDS MySQL: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

    # 8) Log resource in resources_created.json
    rds_entry = None
    if "resources" not in resources:
        resources["resources"] = []

    for r in resources["resources"]:
        if r.get("type") == "rds_instance" and r.get("db_instance_id") == db_instance_id:
            rds_entry = r
            break

    if not rds_entry:
        rds_entry = {
            "type": "rds_instance",
            "db_instance_id": db_instance_id,
            "engine": "mysql",
            "endpoint": endpoint,
            "port": port,
            "db_name": final_db_name,
            "region": region_name
        }
        resources["resources"].append(rds_entry)

    rds_entry["master_username"] = master_username
    rds_entry["master_password"] = master_password

    save_resources_file(resources)
    print(f"Saved resource info for '{db_instance_id}' in resources_created.json.\n")

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
    import time
    from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

    resources = load_resources_file()

    # Prompt for AWS creds/region if not provided
    if not aws_access_key_id:
        aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (input hidden): ", mask='*')
    if not aws_secret_access_key:
        aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (input hidden): ", mask='*')
    if not region_name:
        region_name = input("Enter AWS region name [us-east-1]: ").strip() or "us-east-1"

    # Initialize S3 session/client
    s3_session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )
    s3 = s3_session.client('s3')

    # Generate a temporary bucket name like: dspm-data-gen-1679516814
    epoch_time = int(time.time())
    bucket_name = f"dspm-data-gen-{epoch_time}"
    print(f"Using temporary bucket name: {bucket_name}")
    # We'll still let user pick the object name
    object_name = input("Enter the S3 object name [fake_data.csv]: ").strip() or "fake_data.csv"

    # Attempt to create the temporary bucket
    print(f"Creating temporary bucket '{bucket_name}' in region '{region_name}'...")
    try:
        # For regions other than us-east-1, we must specify a LocationConstraint
        if region_name == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region_name}
            )
        print(f"Bucket '{bucket_name}' created successfully.")
    except ClientError as e:
        print(f"Error creating bucket '{bucket_name}': {e}")
        return

    # Initialize Faker
    generator = faker.Faker()

    # Generate CSV data in memory
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

        # Log this new S3 resource in resources file
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


def cleanup_resources(aws_access_key_id=None, aws_secret_access_key=None):
    """
    Reads from resources_created.json, asks once for AWS credentials if needed,
    then for each resource, asks if you'd like to delete it.
    If yes, performs deletion logic; if no, skips it.
    On successful deletion, removes that resource from the file.
    """
    import boto3
    import psycopg2
    import mysql.connector

    # 1) Load the resources file
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

    # 2) Check if we have any AWS resources
    aws_resources_present = any(
        r.get("type") in ("dynamodb", "redshift", "redshift_cluster", "s3", "rds_instance")
        for r in data["resources"]
    )
    print("\nResources to clean up:")
    print((aws_access_key_id, aws_secret_access_key))
    if aws_access_key_id is None or aws_secret_access_key is None:
        print("\nNo AWS credentials provided. Will prompt for them if needed.")
    else:
        print("\nUsing provided AWS credentials for cleanup.")

    # If we have any AWS resources, ensure we have creds
    if aws_resources_present and (aws_access_key_id is None or aws_secret_access_key is None):
        print("\nWe have AWS resources to delete. Please provide your AWS credentials once.")
        aws_access_key_id = maskpass.askpass(prompt="Enter AWS Access Key ID (hidden): ", mask='*')
        aws_secret_access_key = maskpass.askpass(prompt="Enter AWS Secret Access Key (hidden): ", mask='*')
        print("\nGot AWS credentials. Will use them for all AWS resources needing cleanup.\n")

    print("Cleaning up / Destroying resources created by this script...")

    resources_to_remove = []  # we'll remove these after successful deletion

    for idx, resource in enumerate(data["resources"]):
        rtype = resource.get("type", "")

        # 3) Create a display name for the resource
        if rtype  == "rds_instance":
            name_for_display = f"RDS instance '{resource['db_instance_id']}' (engine '{resource.get('engine', 'mysql')}')"
        elif rtype == "dynamodb":
            name_for_display = f"DynamoDB table '{resource['table_name']}' in region '{resource['region']}'"
        elif rtype == "redshift":
            name_for_display = f"Redshift table '{resource['table']}' in DB '{resource['database']}' on '{resource['host']}:{resource['port']}'"
        elif rtype == "redshift_cluster":
            name_for_display = f"Redshift cluster '{resource['cluster_identifier']}'"
        elif rtype == "s3":
            name_for_display = f"S3 object '{resource['object_key']}' in bucket '{resource['bucket']}' (region '{resource['region']}')"
        else:
            name_for_display = f"Unknown resource type: {rtype}."

        # 4) Ask user if they want to delete
        confirm = input(
            f"\nWould you like to delete this resource? {name_for_display} (yes/no) [yes]: ").strip().lower() or "yes"
        if confirm not in ("yes", "y"):
            print(f"Skipping deletion of {name_for_display}.")
            continue

        deleted_successfully = False

        # 5) Perform deletion
        if rtype == "s3":
            # Deleting both object and bucket
            print(f"\nDeleting {name_for_display} ...")
            region = resource["region"]
            s3_session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region
            )
            s3_client = s3_session.client('s3')
            bucket_name = resource["bucket"]
            object_key = resource["object_key"]

            # 1) Delete the object
            try:
                s3_client.delete_object(Bucket=bucket_name, Key=object_key)
                print(f"S3 object '{object_key}' deleted.")
            except ClientError as e:
                print(f"Could not delete S3 object '{object_key}': {e}")
                # If deleting the object fails, we won't try to delete the bucket
                # or remove from resources
                continue

            # 2) Delete the bucket
            try:
                s3_client.delete_bucket(Bucket=bucket_name)
                print(f"S3 bucket '{bucket_name}' deleted.")
                deleted_successfully = True
            except ClientError as e:
                print(f"Could not delete S3 bucket '{bucket_name}': {e}")



        elif rtype == "dynamodb":

            # Example DynamoDB table deletion if the resource is logged as {"type":"dynamodb",...}

            print(f"\nDeleting DynamoDB table '{resource.get('table_name')}' in region '{resource.get('region')}'...")

            region = resource.get("region", "us-east-1")

            aws_session = boto3.Session(

                aws_access_key_id=aws_access_key_id,

                aws_secret_access_key=aws_secret_access_key,

                region_name=region

            )

            ddb_client = aws_session.client("dynamodb")

            table_name = resource.get("table_name", "fake_data")

            deleted_successfully = False

            try:

                ddb_client.delete_table(TableName=table_name)

                waiter = ddb_client.get_waiter("table_not_exists")

                waiter.wait(TableName=table_name)

                print(f"Deleted DynamoDB table '{table_name}'.")

                deleted_successfully = True

            except ClientError as ce:

                print(f"Error deleting DynamoDB table '{table_name}': {ce}")


        elif rtype == "redshift":

            # "type": "redshift" might indicate a single table on an existing cluster

            print(
                f"\nDeleting Redshift table '{resource.get('table')}' from DB '{resource.get('database')}' on host '{resource.get('host')}:{resource.get('port')}'...")

            user = input("Enter Redshift user: ").strip()

            password = maskpass.askpass(prompt="Enter Redshift password (hidden): ", mask='*')

            deleted_successfully = False

            try:

                import psycopg2

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

                cursor.close()

                conn.close()

                print(f"Dropped Redshift table '{resource['table']}'.")

                deleted_successfully = True

            except Exception as e:

                print(f"Could not drop Redshift table '{resource['table']}': {e}")


        elif rtype == "redshift_cluster":

            # "type": "redshift_cluster" means we remove an entire cluster, possibly dropping a schema/table first

            print(f"\nDeleting Redshift cluster '{resource.get('cluster_identifier')}'...")

            import psycopg2

            deleted_successfully = False

            user = resource.get("master_username", "admin")

            password = resource.get("master_password", "")

            host = resource.get("host", "")

            port = resource.get("port", 5439)

            db_name = resource.get("database", "dev")

            schema = resource.get("schema", "fake_schema")

            table = resource.get("table", "fake_data")

            region = resource.get("region", "us-east-1")

            # Attempt to drop table & schema

            try:

                conn = psycopg2.connect(dbname=db_name, user=user, password=password, host=host, port=port)

                cursor = conn.cursor()

                cursor.execute(f"DROP TABLE IF EXISTS {schema}.{table}")

                cursor.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

                conn.commit()

                cursor.close()

                conn.close()

                print(f"Dropped table '{schema}.{table}' and schema '{schema}'.")

            except Exception as e:

                print(f"Could not drop Redshift table/schema: {e}")

            # Now delete cluster

            redshift_client = boto3.client(

                "redshift",

                region_name=region,

                aws_access_key_id=aws_access_key_id,

                aws_secret_access_key=aws_secret_access_key

            )

            try:

                redshift_client.delete_cluster(

                    ClusterIdentifier=resource["cluster_identifier"],

                    SkipFinalClusterSnapshot=True

                )

                waiter = redshift_client.get_waiter("cluster_deleted")

                waiter.wait(ClusterIdentifier=resource["cluster_identifier"])

                print(f"Redshift cluster '{resource['cluster_identifier']}' fully deleted.")

                deleted_successfully = True

            except Exception as e:

                print(f"Could not delete Redshift cluster '{resource['cluster_identifier']}': {e}")


        elif rtype == "rds_instance":

            # For example, "RDS instance 'DSPM-Data-Gen-MySQL' (engine 'mysql')"

            engine = resource.get("engine", "mysql")

            db_instance_id = resource["db_instance_id"]

            region = resource.get("region", "us-east-1")

            endpoint = resource.get("endpoint", "")

            port = resource.get("port", 3306)

            final_db_name = resource.get("db_name", "test_db")

            user = resource.get("master_username", "admin")

            pw = resource.get("master_password", "")

            print(f"\nDeleting RDS instance '{db_instance_id}' with engine '{engine}' in region '{region}'...")

            # If the engine is MySQL or MariaDB, attempt to drop 'fake_data' table

            if engine in ("aurora-mysql", "mysql", "mariadb"):

                print("Attempting to drop the 'fake_data' table from RDS MySQL instance (if it exists).")

                try:

                    import mysql.connector

                    conn = mysql.connector.connect(

                        host=endpoint,

                        user=user,

                        password=pw,

                        database=final_db_name,

                        port=port

                    )

                    cursor = conn.cursor()

                    cursor.execute("DROP TABLE IF EXISTS fake_data")

                    conn.commit()

                    cursor.close()

                    conn.close()

                    print("Dropped 'fake_data' table (if it existed).")

                except Exception as e:

                    print(f"Could not drop table 'fake_data': {e}")


            # If the engine is Postgres, attempt to drop 'fake_data'

            elif engine == "postgres":

                print("Attempting to drop the 'fake_data' table from RDS Postgres instance (if it exists).")

                try:

                    import psycopg2

                    conn = psycopg2.connect(

                        dbname=final_db_name,

                        user=user,

                        password=pw,

                        host=endpoint,

                        port=port

                    )

                    cursor = conn.cursor()

                    cursor.execute("DROP TABLE IF EXISTS fake_data")

                    conn.commit()

                    cursor.close()

                    conn.close()

                    print("Dropped 'fake_data' table (if it existed).")

                except Exception as e:

                    print(f"Could not drop table 'fake_data': {e}")

            # Now delete the DB instance

            import boto3

            from botocore.exceptions import ClientError

            rds_client = boto3.client(

                "rds",

                region_name=region,

                aws_access_key_id=aws_access_key_id,

                aws_secret_access_key=aws_secret_access_key

            )

            deleted_successfully = False

            try:

                rds_client.delete_db_instance(

                    DBInstanceIdentifier=db_instance_id,

                    SkipFinalSnapshot=True

                )

                print(f"RDS instance '{db_instance_id}' is being deleted. Waiting for it to vanish...")

                # Wait until the DBInstanceNotFound error occurs

                while True:

                    time.sleep(30)

                    try:

                        desc = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)

                        status = desc["DBInstances"][0]["DBInstanceStatus"]

                        print(f"Current status: {status} (still waiting for 'DBInstanceNotFound')")

                    except ClientError as e:

                        if "DBInstanceNotFound" in str(e):

                            print(f"RDS instance '{db_instance_id}' is fully deleted.")

                            deleted_successfully = True

                            break

                        else:

                            print(f"Error while checking DB instance: {e}")

                            break

            except Exception as e:

                print(f"Error deleting RDS instance '{db_instance_id}': {e}")

            # If deletion was fully successful, set the flag

            if deleted_successfully:
                resources_to_remove.append(idx)

                print(f"Successfully deleted RDS instance '{db_instance_id}', removing from resources file.")


        else:
            print(f"\nUnknown resource type: {rtype}. Skipping.")

        # 6) If successfully deleted, mark for removal
        if deleted_successfully:
            resources_to_remove.append(idx)
            print(f"Successfully deleted {name_for_display}, will remove from resources file.")

    # 7) Remove them in reverse order to avoid index shifting
    for idx in sorted(resources_to_remove, reverse=True):
        del data["resources"][idx]

    save_resources_file(data)
    print("\nCleanup complete. You can now safely remove the resources file if desired.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate and insert fake data into various services, or cleanup existing resources."
    )
    parser.add_argument("--cleanup", action="store_true",
                        help="If set, script only runs cleanup for previously created resources, ignoring other arguments.")

    # If not doing cleanup, the user may supply service/rows as normal
    parser.add_argument("--service", type=str,
                        help="Comma-separated list of services or 'all'. Options: mysql, dynamodb, redshift, s3, all.")
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
        cleanup_resources(args.aws_access_key_id, args.aws_secret_access_key)
        sys.exit(0)

    valid_services = ["mysql",  "dynamodb", "redshift", "s3"]
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
        if svc == "mysql":
            insert_data_aws_mysql(
                num_rows,
                aws_access_key_id=args.aws_access_key_id,
                aws_secret_access_key=args.aws_secret_access_key,
                region_name=args.aws_region
            )

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
