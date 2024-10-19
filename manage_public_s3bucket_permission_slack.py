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
    filename='s3_public_access_removal.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configuration Variables
OUTPUT_CSV = 'public_s3_buckets.csv'

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
                file=file_path,
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

def get_all_regions():
    """Retrieve all available AWS regions for S3."""
    try:
        ec2_client = boto3.client('ec2', region_name='us-east-1')  # Initial region to fetch all regions
        regions_response = ec2_client.describe_regions(AllRegions=True)
        regions = [region['RegionName'] for region in regions_response['Regions'] if region['OptInStatus'] in ['opt-in-not-required', 'opted-in']]
        logging.info(f"Retrieved {len(regions)} regions.")
        return regions
    except ClientError as e:
        logging.error(f"Failed to retrieve AWS regions: {e}")
        sys.exit(1)

def check_bucket_public_access(s3_client, bucket_name):
    """Check if Block Public Access is fully enabled for the bucket and return detailed information."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        public_access_block = response['PublicAccessBlockConfiguration']

        # Collect all missing settings
        missing_blocks = []
        if not public_access_block.get('BlockPublicAcls', False):
            missing_blocks.append("BlockPublicAcls")
        if not public_access_block.get('IgnorePublicAcls', False):
            missing_blocks.append("IgnorePublicAcls")
        if not public_access_block.get('BlockPublicPolicy', False):
            missing_blocks.append("BlockPublicPolicy")
        if not public_access_block.get('RestrictPublicBuckets', False):
            missing_blocks.append("RestrictPublicBuckets")

        # If any setting is missing, return False along with missing settings
        if missing_blocks:
            return False, missing_blocks
        else:
            return True, []

    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            # No public access block configuration means the bucket is potentially public
            return False, ["NoPublicAccessBlock"]
        else:
            logging.error(f"Error checking public access for bucket {bucket_name}: {e}")
            return False, ["ErrorCheckingAccess"]

def record_bucket_details(buckets):
    """Write the S3 buckets with missing public access blocks to a CSV file."""
    try:
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['BucketName', 'Region', 'MissingBlocks']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for bucket in buckets:
                writer.writerow(bucket)
        logging.info(f"Recorded S3 bucket details to {OUTPUT_CSV}.")
    except Exception as e:
        logging.error(f"Failed to write S3 bucket details to CSV: {e}")

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Identify and optionally remove public access from S3 buckets.')
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run without making any changes.')
    parser.add_argument('--region', type=str, help='Specify a single AWS region to process.')
    parser.add_argument('--bucket', type=str, help='Specify a single S3 bucket to process.')
    return parser.parse_args()

def main():
    # Parse command-line arguments
    args = parse_arguments()
    is_dry_run = args.dry_run
    specified_region = args.region
    specified_bucket = args.bucket

    # Determine regions to process
    if specified_region:
        regions = [specified_region]
        logging.info(f"Region override set to: {specified_region}")
    else:
        regions = get_all_regions()

    non_compliant_buckets = []

    if specified_bucket:
        # Process the specified bucket only
        s3_client = boto3.client('s3', region_name=specified_region)

        # Check public access for the specified bucket
        is_protected, missing_blocks = check_bucket_public_access(s3_client, specified_bucket)
        if not is_protected:
            bucket_location = s3_client.get_bucket_location(Bucket=specified_bucket)['LocationConstraint'] or 'us-east-1'
            if specified_region and bucket_location != specified_region:
                logging.info(f"Bucket '{specified_bucket}' is not in the specified region '{specified_region}'. Skipping.")
            else:
                non_compliant_buckets.append({
                    'BucketName': specified_bucket,
                    'Region': bucket_location,
                    'MissingBlocks': ', '.join(missing_blocks)
                })
                logging.info(f"Bucket '{specified_bucket}' in region '{bucket_location}' has potentially public access.")

    else:
        # Iterate over all regions to find non-compliant buckets
        for region in regions:
            logging.info(f"Processing region: {region}")
            s3_client = boto3.client('s3', region_name=region)

            # List all S3 buckets
            try:
                response = s3_client.list_buckets()
                for bucket in response['Buckets']:
                    bucket_name = bucket['Name']
                    is_protected, missing_blocks = check_bucket_public_access(s3_client, bucket_name)
                    if not is_protected:
                        bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint'] or 'us-east-1'
                        if specified_region and bucket_location != specified_region:
                            logging.info(f"Bucket '{bucket_name}' is not in the specified region '{specified_region}'. Skipping.")
                        else:
                            non_compliant_buckets.append({
                                'BucketName': bucket_name,
                                'Region': bucket_location,
                                'MissingBlocks': ', '.join(missing_blocks)
                            })
                            logging.info(f"Bucket '{bucket_name}' in region '{bucket_location}' has potentially public access.")
            except ClientError as e:
                logging.error(f"Error listing buckets in region {region}: {e}")

    if not non_compliant_buckets:
        logging.info("No S3 buckets with public access issues found across all regions.")
        send_slack_alert(":tada: No S3 buckets with public access issues found in the scanned regions.")
        return

    # Record details to CSV
    record_bucket_details(non_compliant_buckets)
    send_slack_alert(":page_facing_up: **S3 Buckets Without Full Public Access Block Report**", OUTPUT_CSV)

    if is_dry_run:
        logging.info("Dry run mode enabled. No changes will be made.")
        for bucket in non_compliant_buckets:
            logging.info(f"[Dry Run] Would remove public access from bucket {bucket['BucketName']} in region {bucket['Region']}.")
        return

    # Prompt user for confirmation
    user_input = input("\nDo you want to remove the public access from these S3 buckets? (yes/no): ").strip().lower()
    if user_input not in ['yes', 'y']:
        logging.info("Operation aborted by the user. No changes were made.")
        return

    # Proceed to remove public access
    for bucket in non_compliant_buckets:
        bucket_name = bucket['BucketName']
        region = bucket['Region']
        s3_client = boto3.client('s3', region_name=region)
        try:
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            logging.info(f"Removed public access from bucket '{bucket_name}' in region '{region}'.")
            send_slack_alert(f":white_check_mark: Successfully removed public access from bucket '{bucket_name}' in region '{region}'.")
        except ClientError as e:
            logging.error(f"Failed to remove public access from bucket '{bucket_name}' in region '{region}': {e}")
            send_slack_alert(f":x: Failed to remove public access from bucket '{bucket_name}' in region '{region}'. Error: {e.response['Error']['Message']}")

    logging.info("Completed removal of public access from identified S3 buckets.")
    send_slack_alert(":information_source: **S3 Public Access Removal Script Completed**")

if __name__ == "__main__":
