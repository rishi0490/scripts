import os
import sys
import boto3
import logging
import csv
import argparse
from botocore.exceptions import ClientError
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Initialize logging to file
logging.basicConfig(
    filename='teleport_public_removal.log',
    level=logging.DEBUG,  # Changed to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configuration Variables
CIDR_IP_TO_REMOVE = '0.0.0.0/0'
PORTS_TO_REMOVE = [3023, 3025]  # Teleport ports
OUTPUT_CSV = 'public_teleport_security_groups.csv'

# Slack Credentials from environment variables
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL')  # Channel ID where the file will be uploaded

if not SLACK_BOT_TOKEN:
    logging.error("Slack Bot Token not set. Please set the SLACK_BOT_TOKEN environment variable.")
    sys.exit(1)

if not SLACK_CHANNEL:
    logging.error("Slack Channel ID not set. Please set the SLACK_CHANNEL environment variable.")
    sys.exit(1)

# Initialize Slack WebClient
slack_client = WebClient(token=SLACK_BOT_TOKEN)

def send_slack_alert(message, file_path=None):
    """Send a message and optionally a file to Slack via Bot Token."""
    try:
        # Send the message
        response = slack_client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=message
        )
        logging.info("Slack message sent successfully.")
        logging.debug(f"Slack Message Response: {response.data}")

        # If a file path is provided, upload the file using files_upload_v2
        if file_path:
            response = slack_client.files_upload_v2(
                channel=SLACK_CHANNEL,
                initial_comment=message,
                file=file_path,  # For files_upload_v2, provide the file path as a string
                title=os.path.basename(file_path),
                filetype='csv'
            )
            if response["ok"]:
                logging.info("CSV file uploaded to Slack successfully.")
                logging.debug(f"Slack File Upload Response: {response.data}")
            else:
                logging.error(f"Failed to upload file to Slack: {response['error']}")
    except SlackApiError as e:
        logging.error(f"Slack API Error: {e.response['error']}")
    except Exception as e:
        logging.error(f"Exception occurred while sending Slack alert: {e}")

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Identify and optionally remove public Teleport access from AWS security groups.')
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run without making any changes.')
    parser.add_argument('--region', type=str, help='Specify a single AWS region to process.')
    return parser.parse_args()

def get_all_regions():
    """Retrieve all available AWS regions for EC2."""
    try:
        ec2_client = boto3.client('ec2', region_name='us-east-1')  # Initial region to fetch all regions
        regions_response = ec2_client.describe_regions(AllRegions=True)
        regions = [region['RegionName'] for region in regions_response['Regions'] if region['OptInStatus'] in ['opt-in-not-required', 'opted-in']]
        logging.info(f"Retrieved {len(regions)} regions.")
        return regions
    except ClientError as e:
        logging.error(f"Failed to retrieve AWS regions: {e}")
        sys.exit(1)

def find_security_groups_with_public_teleport(ec2_client):
    """Find security groups that have Teleport open to the public."""
    try:
        response = ec2_client.describe_security_groups()
        security_groups_with_public_teleport = []

        for sg in response['SecurityGroups']:
            open_ports = []
            for permission in sg.get('IpPermissions', []):
                if (permission.get('IpProtocol') == 'tcp' and
                    permission.get('FromPort') in PORTS_TO_REMOVE and
                    permission.get('ToPort') in PORTS_TO_REMOVE):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == CIDR_IP_TO_REMOVE:
                            open_ports.append(permission.get('FromPort'))
                            break  # Avoid duplicate port entries
            if open_ports:
                security_groups_with_public_teleport.append({
                    'SecurityGroup': sg,
                    'OpenPorts': open_ports
                })
                logging.info(f"Security group {sg['GroupId']} in region {ec2_client.meta.region_name} has Teleport open to the public on ports {open_ports}.")

        return security_groups_with_public_teleport

    except ClientError as e:
        logging.error(f"Error finding security groups with public Teleport in region {ec2_client.meta.region_name}: {e}")
        return []

def get_instances_using_security_group(ec2_resource, sg_id):
    """Retrieve instances associated with a specific security group."""
    try:
        filters = [{
            'Name': 'instance.group-id',
            'Values': [sg_id]
        }]
        instances = ec2_resource.instances.filter(Filters=filters)
        instance_details = []
        for instance in instances:
            # Retrieve the 'Name' tag if it exists
            name = 'N/A'
            if instance.tags:
                for tag in instance.tags:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
            instance_details.append({
                'InstanceId': instance.id,
                'InstanceName': name,
                'InstanceType': instance.instance_type,
                'Region': ec2_resource.meta.client.meta.region_name
            })
        return instance_details
    except ClientError as e:
        logging.error(f"Error retrieving instances for security group {sg_id} in region {ec2_resource.meta.client.meta.region_name}: {e}")
        return []

def record_security_group_details(all_sgs_details):
    """Write the security groups and associated instances to a CSV file."""
    try:
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Region', 'SecurityGroupId', 'SecurityGroupName', 'Description', 'Ports', 'InstanceId', 'InstanceName', 'InstanceType']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for sg_detail in all_sgs_details:
                sg = sg_detail['SecurityGroup']
                instances = sg_detail['Instances']
                sg_name = sg.get('GroupName', 'N/A')
                sg_description = sg.get('Description', 'N/A')
                ports_str = ', '.join(map(str, sg_detail['OpenPorts'])) if sg_detail['OpenPorts'] else 'N/A'

                if instances:
                    for instance in instances:
                        writer.writerow({
                            'Region': sg_detail['Region'],
                            'SecurityGroupId': sg['GroupId'],
                            'SecurityGroupName': sg_name,
                            'Description': sg_description,
                            'Ports': ports_str,
                            'InstanceId': instance['InstanceId'],
                            'InstanceName': instance['InstanceName'],
                            'InstanceType': instance['InstanceType']
                        })
                else:
                    writer.writerow({
                        'Region': sg_detail['Region'],
                        'SecurityGroupId': sg['GroupId'],
                        'SecurityGroupName': sg_name,
                        'Description': sg_description,
                        'Ports': ports_str,
                        'InstanceId': 'N/A',
                        'InstanceName': 'N/A',
                        'InstanceType': 'N/A'
                    })
        logging.info(f"Recorded security group details to {OUTPUT_CSV}.")
    except Exception as e:
        logging.error(f"Failed to write security group details to CSV: {e}")

def remove_teleport_inbound_rule(ec2_client, sg_id, port):
    """Remove the inbound Teleport rule from a security group."""
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': CIDR_IP_TO_REMOVE}]
                }
            ]
        )
        logging.info(f"Removed inbound rule for {CIDR_IP_TO_REMOVE} on port {port} from security group {sg_id} in region {ec2_client.meta.region_name}.")

        # Send Slack alert
        message = (f":white_check_mark: **Removed Public Teleport Access**\n"
                   f"**Security Group ID:** `{sg_id}`\n"
                   f"**Region:** `{ec2_client.meta.region_name}`\n"
                   f"**Port:** `{port}`")
        send_slack_alert(message)

        return True
    except ClientError as e:
        logging.error(f"Failed to remove rule for security group {sg_id} on port {port} in region {ec2_client.meta.region_name}: {e}")

        # Extract error message if available
        error_message = e.response['Error']['Message'] if 'Error' in e.response else str(e)

        # Send Slack alert for failure
        message = (f":x: **Failed to Remove Public Teleport Access**\n"
                   f"**Security Group ID:** `{sg_id}`\n"
                   f"**Region:** `{ec2_client.meta.region_name}`\n"
                   f"**Port:** `{port}`\n"
                   f"**Error:** `{error_message}`")
        send_slack_alert(message)

        return False

def main():
    # Parse command-line arguments
    args = parse_arguments()
    is_dry_run = args.dry_run
    AWS_REGION_OVERRIDE = args.region

    # Determine regions to process
    if AWS_REGION_OVERRIDE:
        regions = [AWS_REGION_OVERRIDE]
        logging.info(f"Region override set to: {AWS_REGION_OVERRIDE}")
    else:
        regions = get_all_regions()

    all_sgs_details = []

    for region in regions:
        logging.info(f"Processing region: {region}")
        print(f"Processing region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        ec2_resource = boto3.resource('ec2', region_name=region)

        sgs_with_public_teleport = find_security_groups_with_public_teleport(ec2_client)

        for sg_entry in sgs_with_public_teleport:
            sg = sg_entry['SecurityGroup']
            open_ports = sg_entry['OpenPorts']
            instances = get_instances_using_security_group(ec2_resource, sg['GroupId'])
            all_sgs_details.append({
                'Region': region,
                'SecurityGroup': sg,
                'OpenPorts': open_ports,
                'Instances': instances
            })

    if not all_sgs_details:
        logging.info("No security groups with public Teleport access found across all regions.")
        print("No security groups with public Teleport access found across all regions.")

        # Send Slack alert
        message = ":tada: No security groups with public Teleport access were found in the scanned regions."
        send_slack_alert(message)

        return

    # Record details to CSV
    record_security_group_details(all_sgs_details)
    print(f"Details of security groups with public Teleport access have been recorded in '{OUTPUT_CSV}'.")
    logging.info(f"Details recorded in '{OUTPUT_CSV}'.")

    # Send CSV file to Slack
    message = ":page_facing_up: **Teleport Public Access Security Groups Report**"
    send_slack_alert(message, OUTPUT_CSV)
    logging.info("Uploaded CSV report to Slack.")

    # Display summary to the user
    print("\nSummary of Security Groups with Public Teleport Access:")
    for sg_detail in all_sgs_details:
        sg = sg_detail['SecurityGroup']
        region = sg_detail['Region']
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'N/A')
        ports_str = ', '.join(map(str, sg_detail['OpenPorts'])) if sg_detail['OpenPorts'] else 'N/A'
        print(f"- Region: {region}, Security Group ID: {sg_id}, Name: {sg_name}, Port(s): {ports_str}")

    if is_dry_run:
        print("\nDry run mode enabled. No changes will be made.")
        logging.info("Dry run mode enabled. No security groups will be modified.")
        # Optionally, you can also print what would have been done
        for sg_detail in all_sgs_details:
            sg = sg_detail['SecurityGroup']
            region = sg_detail['Region']
            sg_id = sg['GroupId']
            ports_str = ', '.join(map(str, sg_detail['OpenPorts'])) if sg_detail['OpenPorts'] else 'N/A'
            print(f"[Dry Run] Would remove public Teleport access on port(s) {ports_str} from Security Group {sg_id} in region {region}.")
            logging.info(f"Dry run: Would remove public Teleport access on port(s) {ports_str} from Security Group {sg_id} in region {region}.")
        return

    # Prompt user for confirmation (only if not dry run)
    user_input = input("\nDo you want to remove the public Teleport access from these security groups? (yes/no): ").strip().lower()
    if user_input not in ['yes', 'y']:
        print("Operation aborted by the user. No changes were made.")
        logging.info("Operation aborted by the user. No security groups were modified.")
        return

    # Proceed to remove Teleport rules
    for sg_detail in all_sgs_details:
        sg = sg_detail['SecurityGroup']
        region = sg_detail['Region']
        sg_id = sg['GroupId']
        ec2_client = boto3.client('ec2', region_name=region)
        open_ports = sg_detail['OpenPorts']
        for port in open_ports:
            success = remove_teleport_inbound_rule(ec2_client, sg_id, port)
            if success:
                print(f"Successfully removed public Teleport access on port {port} from Security Group {sg_id} in region {region}.")
            else:
                print(f"Failed to remove public Teleport access on port {port} from Security Group {sg_id} in region {region}. Check logs for details.")

    # Send completion Slack alert
    message = (f":information_source: **Teleport Public Access Removal Script Completed**\n"
               f"Regions Scanned: `{len(regions)}`\n"
               f"Security Groups Identified: `{len(all_sgs_details)}`")
    send_slack_alert(message)

    print("\nOperation completed. Check 'teleport_public_removal.log' for detailed logs.")
    logging.info("Completed removal of public Teleport access from identified security groups.")

if __name__ == "__main__":
    main()

