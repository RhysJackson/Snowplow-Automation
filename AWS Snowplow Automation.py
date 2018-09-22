##################
# SETUP
##################

# Script written for Python 3

# Before running the script you will need to install...
# 'boto3' by using the command: pip install boto3
# 'paramiko' by using the command: pip install paramiko

import urllib.request
import boto3
from botocore.exceptions import ClientError
import time
import botocore
import paramiko


##################
# CONFIGURATION
##################
# All variables must be defined


### AWS REGION ###
# The region in which you want to run Snowplow
snowplow_region = 'eu-west-1'

### AWS CREDENTIALS ###
# Create these keys in your Amazon AWS account by creating a user with 'Programmatic access'
# https://console.aws.amazon.com/iam/home#/home
# For testing purposes, give the user the existing policy 'Administrator Access'
# NOTE: In production, policies should be limited only to required functionality
aws_access_key_id=''
aws_secret_access_key=''

### CLOUDFRONT (CDN) ###
# Name for your Cloudfront Distribution (CDN for the tracking pixel)
cloudfront_deployment_name = 'snowplow-testing'


### S3 BUCKETS (file storage) ###
# Stores the Snowplow tracker pixel 
pixel_bucket_name = 'rhys-snowplow-automation'

# Stores the raw Cloudfront logs, ready for processing
cloudfront_logs_bucket = 'rhys-snowplow-automation-logs'

# Stores the logs from the ELT process (useful for debugging)
etl_logs_bucket = 'rhys-snowplow-automation-etl-logs'

# Stores the enriched snowplow data at every step of the enrichment process
archive_bucket_name = 'rhys-snowplow-automation-archive'


### WEBSITE ID ###
# An arbtirary identifier for the website you'll run the JavaScript tracking code on.
site_id = 'snowplow_testing'


### SNOWPLOW ELASTIC MAP REDUCE RUNNER ###
# The Snowplow Elastic Map Reduce runner version to use
# All versions available here: http://dl.bintray.com/snowplow/snowplow-generic/
EmrEtlVersion = 'r109_lambaesis'

# Configure the cron schedule expression to run the enrichment
# https://crontab.guru/
# E.g. 0 6 * * 1 == Run at 6am every Monday
enrichment_schedule = '0 6 * * 1'

### POSTGRESQL ###
# Define passwords for the various postgresql users
# Admin password
postgres_admin_pass = ''
# Power users are database admins
postgres_power_user_pass = ''
# 'Other' user is suitable for analysts wanting to query data
postgres_other_user_pass = ''
# Storageloader is used by the Elastic Map Reduce runner to load data into the database
postgres_storageloader_pass = ''


boto3.setup_default_session(region_name=snowplow_region,
                           aws_access_key_id=aws_access_key_id,
                           aws_secret_access_key=aws_secret_access_key)


### NO FURTHER CONFIGURATION REQUIRED BELOW THIS LINE ###


##################
# CREATE THE S3 PIXEL BUCKET
##################
# S3 is Amazon's file storage service
# It stores all the files we need to run Snowplow, including tracking pixel, logs, and enriched/archived data

s3 = boto3.client('s3')

# Function to check if a bucket exists
def bucket_exists(bucket_name):
    bucket = s3.head_bucket(Bucket=bucket_name)
    return True     

# Function to create a bucket
def create_bucket(bucket_name):
    if bucket_exists(bucket_name):
        print('S3 bucket ' + bucket_name + ' has already been configured')
    else:
        print('Creating S3 bucket ' + bucket_name)
        s3.create_bucket(Bucket=bucket_name,
                         CreateBucketConfiguration={
                             'LocationConstraint': snowplow_region
                         })
        while not bucket_exists(bucket_name):
            print('S3 bucket ' + bucket_name + ' not ready, retying in 5 seconds')
            time.sleep(5)
        print(bucket_name + ' bucket created successfully')
    

# Create a bucket to store the Snowplow pixel
create_bucket(pixel_bucket_name)

# Create a bucket to store the Cloudfront logs (the raw hit data)
create_bucket(cloudfront_logs_bucket)

# Create a bucket to store the processing/enriched/archived Snowplow data
create_bucket(archive_bucket_name)

# Create a bucket to store the logs from AWS Elastic Map Reduce (enrichment process)
create_bucket(etl_logs_bucket)

# Download the Snowplow 1x1 pixel image
print('Downloading Snowplow pixel')
urllib.request.urlretrieve('https://github.com/snowplow/snowplow/raw/master/2-collectors/cloudfront-collector/static/i', 'i')

# Upload the pixel to the bucket
s3.put_object(Bucket = pixel_bucket_name,
              ACL='public-read',
              Body='i',
              Key='i',
              Metadata={
                  'ContentType': 'image/gif'
              })


# Define the required folders within the archive bucket
required_folders = [
    'processing/'
    'archive/raw/',
    'archive/enriched/',
    'archive/shredded/',
    'enriched/good/',
    'enriched/bad/',
    'shredded/good/',
    'shredded/bad/'
]

# Loop through each folder and create it within the bucket
# s3_client = boto3.client('s3')
for archive_bucket in required_folders:
    s3.put_object(
        Bucket=archive_bucket_name,
        Body='',
        Key=archive_bucket
    )
    print("Created " + archive_bucket)


##################
# CREATE AMAZON CLOUDFRONT DISTRIBUTION
##################
# Cloudfront is Amazon's CDN service
# It distributes our Snowplow pixel across servers all over the world
# This helps ensure high availability and download speed for end users

cf = boto3.client('cloudfront')


# Create the cloudfront configuration
cloudfront_dist_config = {
    'CallerReference': cloudfront_deployment_name,
    'Comment': 'Snowplow Pixel Distribution',
    'Origins': {
        'Quantity': 1,
        'Items': [{
            'Id': pixel_bucket_name,
            'DomainName': pixel_bucket_name + '.s3.amazonaws.com',
            'S3OriginConfig': {
                'OriginAccessIdentity': ''
            }
        }]
    },
    'Logging': {
        'Enabled': True,
        'IncludeCookies': True,
        'Bucket': cloudfront_logs_bucket + '.s3.amazonaws.com',
        'Prefix': ''
    },
    'DefaultCacheBehavior': {
        'TargetOriginId': pixel_bucket_name,
        'ForwardedValues': {
            'Cookies': {
                'Forward': 'all'
            },
            'QueryString': True,
        },
        'TrustedSigners': {
            'Quantity': 0,
            'Enabled': False
        },
        'ViewerProtocolPolicy': 'redirect-to-https',
        'MinTTL': 1000
    },
    'Comment': '',
    'Enabled': True,
}

# Check if any distributions already exist with the comment 'Snowplow Pixel Distribution'
current_distributions = [x for x in cf.list_distributions()['DistributionList']['Items'] if x['Comment'] == 'Snowplow Pixel Distribution']
if len(current_distributions) > 0:
    # If already exists, get the ID of the distribution
    cf_id = current_distributions[0]['Id']
else:
    # Else create a new distribution
    response = cf.create_distribution(DistributionConfig=cloudfront_dist_config)
    cf_id = response['Distribution']['Id']

    
# Keep checking until the distribution is available - This can take up to 15 minutes(ish)
response = cf.get_distribution(Id=cf_id)
print('CloudFront setup is ' + response['Distribution']['Status'])
while response['Distribution']['Status'] == 'InProgress':
    print('Waiting for CloudFront distribution to be ready, this could take some time. Retrying in 30 seconds')
    time.sleep(30)
    response = cf.get_distribution(Id=cf_id)
    print('CloudFront is ' + response['Distribution']['Status'])

    
# Get the domain name of your cloudfront distribution
cf_domain_name = response['Distribution']['DomainName']


# Test the collector endpoints
def test_endpoint(endpoint_url):
    with urllib.request.urlopen(endpoint_url) as url:
        http_code = url.getcode()
        if(endpoint_url != url.geturl()):
            print('Redirected from ' + endpoint_url + ' to ' + url.geturl())
        if(http_code == 200):
            print('Success! Snowplow pixel is accessible via ' + endpoint_url)
        else:
            print('Error: Snowplow pixel could not be reached via ' + endpoint_url)

# Test http
test_endpoint('http://' + cf_domain_name + '/i')

# Test https
test_endpoint('https://' + cf_domain_name + '/i')


##################
# JAVASCRIPT TRACKING CODE
##################
# This is the tracking code for you to copy and paste onto your website
# It can be fired through a tag manager, or hardcoded to your page template(s)

tracking_code = """
<!-- Snowplow starts plowing -->
<script type="text/javascript">
;(function(p,l,o,w,i,n,g){if(!p[i]){p.GlobalSnowplowNamespace=p.GlobalSnowplowNamespace||[];
p.GlobalSnowplowNamespace.push(i);p[i]=function(){(p[i].q=p[i].q||[]).push(arguments)
};p[i].q=p[i].q||[];n=l.createElement(o);g=l.getElementsByTagName(o)[0];n.async=1;
n.src=w;g.parentNode.insertBefore(n,g)}}(window,document,"script","//d1fc8wv8zag5ca.cloudfront.net/2.6.2/sp.js","snowplow"));

window.snowplow('newTracker', 'cf', '""" + cf_domain_name + """', { // Initialise a tracker
  appId: '""" + site_id + """',
  forceSecureTracker: true
});

window.snowplow('trackPageView');
</script>
<!-- Snowplow stops plowing -->
"""

print('Your tracking code is:')
print(tracking_code)


##################
# EC2 SERVER SETUP
##################
# EC2 is Amazon's compute service, allowing you to rent a server (a.k.a. an 'instance') in the AWS cloud
# One server will be used to kickstart the data enrichment process and host the postgresql database

ec2 = boto3.client('ec2')


# Find default VPC id
default_VPC_id = ec2.describe_vpcs()['Vpcs'][0]['VpcId']


# Create security group named 'EC2 SSH full access'
try:
    response = ec2.create_security_group(
        Description= 'Snowplow EC2 Access',
        GroupName='EC2 SSH full access',
        VpcId=default_VPC_id,
        DryRun=False
    )
    security_group_id = response['GroupId']
except ClientError as e:
    print(e.response['Error']['Message'])
    if e.response['Error']['Code'] == "InvalidGroup.Duplicate":
        security_groups = ec2.describe_security_groups()['SecurityGroups']
        security_group_id = [x for x in security_groups if x['Description'] == 'Snowplow EC2 Access'][0]['GroupId']


# Create SSH ingress rule to allow SSH connections from any IP address
# NOTE: This is NOT recommended for production! SSH access should be restricted only to IPs that require it
try:
    ec2.authorize_security_group_ingress(
        GroupId = security_group_id,
        IpProtocol = 'tcp',
        FromPort = 22,
        ToPort = 22,
        CidrIp = '0.0.0.0/0'
    )
except ClientError as e:
    print(e.response['Error']['Message'])
    
# Create postgres ingress rule to allow connections to the PostgreSQL database from any IP address
# NOTE: This is NOT recommended for production! Database access should be restricted only to IPs that require it
try:
    ec2.authorize_security_group_ingress(
        GroupId = security_group_id,
        IpProtocol = 'tcp',
        FromPort = 5432,
        ToPort = 5432,
        CidrIp = '0.0.0.0/0'
    )
except ClientError as e:
    print(e.response['Error']['Message'])

    
# Create SSH key named 'snowplow-ec2' and save the private key to your computer
try:
    key = ec2.create_key_pair(
        KeyName='snowplow-ec2',
        DryRun=False
    )
    f = open('snowplow-ec2.pem',"w+")
    f.write(key['KeyMaterial'])
    f.close()
except ClientError as e:
    print(e.response['Error']['Message'])
    

# Get list of suitable images
images = ec2.describe_images(Filters = [
    {
        'Name': 'name',
        'Values': ['amzn2-ami-hvm-2.0.????????-x86_64-gp2']
    }, {
        'Name': 'state',
        'Values': ['available']
    }
])


# Get list of current instances using the key 'snowplow-ec2' and are called 'SnowplowEmrEtl'
instances = ec2.describe_instances(Filters = [
    {
        'Name': 'key-name',
        'Values': ['snowplow-ec2']
    }, {
        'Name': 'tag:Name',
        'Values': ['SnowplowEmrEtl']
    }
])


# Create a server if no existing serveris found
if len(instances['Reservations']) == 0:
    print("Creating EC2 Instance")
    response = ec2.run_instances(
        ImageId = images['Images'][0]['ImageId'],
        InstanceType = 't2.micro',
        MinCount = 1,
        MaxCount = 1,
        KeyName = 'snowplow-ec2',
        TagSpecifications = [{
            'ResourceType': 'instance',
            'Tags': [{
                'Key': 'Name',
                'Value': 'SnowplowEmrEtl'
            }]
        }]
    )
    instance_id = response['Instances'][0]['InstanceId']
else:
    print("Instance already exists")
    instance_id = instances['Reservations'][0]['Instances'][0]['InstanceId']
    instance_subnet_id = instances['Reservations'][0]['Instances'][0]['SubnetId']


# Add instance to security group
ec2.modify_instance_attribute(InstanceId = instance_id, Groups = [security_group_id])


instance = ec2.describe_instances(InstanceIds = [instance_id])
instance_hostname = instance['Reservations'][0]['Instances'][0]['PublicDnsName'] 


##################
# SERVER SETUP 
##################
# Define the Snowplow enrichment runner configuration
# https://github.com/snowplow/snowplow/wiki/Common-configuration

start_enrich_cmd = "~/snowplow-emr-etl-runner run -c ~/config/config.yml -r ~/config/iglu_resolver.json -n ~/config/enrichments/ -t ~/config/targets/"
EmrEtlConfig = """
aws:
  # Credentials can be hardcoded or set in environment variables
  access_key_id: """ + aws_access_key_id + """
  secret_access_key: """ + aws_access_secret_access_key + """
  s3:
    region: """ + snowplow_region + """
    buckets:
      assets: s3://snowplow-hosted-assets # DO NOT CHANGE unless you are hosting the jarfiles etc yourself in your own bucket
      jsonpath_assets: # If you have defined your own JSON Schemas, add the s3:// path to your own JSON Path files in your own bucket here
      log: s3://""" + etl_logs_bucket + """
      encrypted: false # Whether the buckets below are enrcrypted using server side encryption (SSE-S3)
      raw:
        in:                  # This is a YAML array of one or more in buckets - you MUST use hyphens before each entry in the array, as below
          - s3://""" + cloudfront_logs_bucket + """     # e.g. s3://my-old-collector-bucket
        processing: s3://""" + archive_bucket_name + """/processing
        archive: s3://""" + archive_bucket_name + """/archive    # e.g. s3://my-archive-bucket/raw
      enriched:
        good: s3://""" + archive_bucket_name + """/enriched/good       # e.g. s3://my-out-bucket/enriched/good
        bad: s3://""" + archive_bucket_name + """/enriched/bad        # e.g. s3://my-out-bucket/enriched/bad
        errors:              # Leave blank unless :continue_on_unexpected_error: set to true below
        archive: s3://""" + archive_bucket_name + """/enriched/archive    # Where to archive enriched events to, e.g. s3://my-archive-bucket/enriched
      shredded:
        good: s3://""" + archive_bucket_name + """/shredded/good       # e.g. s3://my-out-bucket/shredded/good
        bad: s3://""" + archive_bucket_name + """/shredded/bad        # e.g. s3://my-out-bucket/shredded/bad
        errors:              # Leave blank unless :continue_on_unexpected_error: set to true below
        archive: s3://""" + archive_bucket_name + """/shredded/archive    # Where to archive shredded events to, e.g. s3://my-archive-bucket/shredded
  emr:
    ami_version: 5.9.0
    region: """ + snowplow_region + """        # Always set this
    jobflow_role: EMR_EC2_DefaultRole # Created using $ aws emr create-default-roles
    service_role: EMR_DefaultRole     # Created using $ aws emr create-default-roles
    placement:      # Set this if not running in VPC. Leave blank otherwise
    ec2_subnet_id: """ + instance_subnet_id + """ # Set this if running in VPC. Leave blank otherwise
    ec2_key_name: 'snowplow-ec2'
    security_configuration: # Specify your EMR security configuration if needed. Leave blank otherwise
    bootstrap: []           # Set this to specify custom boostrap actions. Leave empty otherwise
    software:
      hbase:                # Optional. To launch on cluster, provide version, "0.92.0", keep quotes. Leave empty otherwise.
      lingual:              # Optional. To launch on cluster, provide version, "1.1", keep quotes. Leave empty otherwise.
    # Adjust your Hadoop cluster below
    jobflow:
      job_name: Snowplow ETL # Give your job a name
      master_instance_type: m1.medium
      core_instance_count: 1
      core_instance_type: m1.medium
      core_instance_ebs:    # Optional. Attach an EBS volume to each core instance.
        volume_size: 100    # Gigabytes
        volume_type: "gp2"
        volume_iops: 400    # Optional. Will only be used if volume_type is "io1"
        ebs_optimized: false # Optional. Will default to true
      task_instance_count: 0 # Increase to use spot instances
      task_instance_type: m1.medium
      task_instance_bid: 0.015 # In USD. Adjust bid, or leave blank for non-spot-priced (i.e. on-demand) task instances
    bootstrap_failure_tries: 3 # Number of times to attempt the job in the event of bootstrap failures
    configuration:
      yarn-site:
        yarn.resourcemanager.am.max-attempts: "1"
      spark:
        maximizeResourceAllocation: "true"
    additional_info:        # Optional JSON string for selecting additional features
collectors:
  format: cloudfront # For example: 'clj-tomcat' for the Clojure Collector, 'thrift' for Thrift records, 'tsv/com.amazon.aws.cloudfront/wd_access_log' for Cloudfront access logs or 'ndjson/urbanairship.connect/v1' for UrbanAirship Connect events
enrich:
  versions:
    spark_enrich: 1.16.0 # Version of the Spark Enrichment process
  continue_on_unexpected_error: false # Set to 'true' (and set :out_errors: above) if you don't want any exceptions thrown from ETL
  output_compression: NONE # Compression only supported with Redshift, set to NONE if you have Postgres targets. Allowed formats: NONE, GZIP
storage:
  versions:
    rdb_loader: 0.14.0
    rdb_shredder: 0.13.1        # Version of the Spark Shredding process
    hadoop_elasticsearch: 0.1.0 # Version of the Hadoop to Elasticsearch copying process
monitoring:
  tags: {} # Name-value pairs describing this job
  logging:
    level: DEBUG # You can optionally switch to INFO for production
  snowplow:
    method: get
    protocol: https
    port: 443
    app_id: snowplow_emr_etl # e.g. snowplow
    collector: """ + cf_domain_name + """ # e.g. d3rkrsqld9gmqf.cloudfront.net
"""

storage_target_config = """
{
    "schema": "iglu:com.snowplowanalytics.snowplow.storage/postgresql_config/jsonschema/1-1-0",
    "data": {
        "name": "PostgreSQL enriched events storage",
        "host": """ + instance_hostname + """,
        "database": "snowplow",
        "port": 5432,
        "sslMode": "DISABLE",
        "username": "storageloader",
        "password": """ + postgres_storageloader_pass + """,
        "schema": "atomic",
        "sshTunnel": null,
        "purpose": "ENRICHED_EVENTS"
    }
}
"""


# Configuration for the 'pg_hba.conf' file
# This configuration allows access to the database from any IP address for the users: power_user, other_user, and storageloader
postgres_conf = """
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# "local" is for Unix domain socket connections only
local   all             all                                     trust
# IPv4 local connections:
host    all             power_user      0.0.0.0/0               md5
host    all             other_user      0.0.0.0/0               md5
host    all             storageloader   0.0.0.0/0               md5
# IPv6 local connections:
host    all             all             ::1/128                 md5
"""


# Create the setup script to run on the server
setup_script = """
#!/bin/bash

echo "Installing Java"
sudo yum install -y java-1.8.0-openjdk.x86_64

echo "Installing postgres"
sudo yum install -y postgresql postgresql-server postgresql-devel postgresql-contrib postgresql-docs

echo "Initialising Database"
sudo service postgresql initdb

echo "Configuring postgres pg_hba.conf file"
sudo echo """ + postgres_conf + """ > '/var/lib/pgsql/data/pg_hba.conf'

echo "Configuring postgres postgresql.conf file"
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses='*'/" /var/lib/pgsql/data/postgresql.conf
sudo sed -i "s/#port = 5432/port = 5432/" /var/lib/pgsql/data/postgresql.conf

# Starting postgresql database
sudo service postgresql start

# Add password to postgres user
sudo -u postgres psql -U postgres -c "ALTER USER postgres WITH PASSWORD '""" + postgres_admin_pass + """';"

echo "Setting up each of the Snowplow database users"
sudo -u postgres psql -U postgres -c "CREATE USER power_user SUPERUSER;"
sudo -u postgres psql -U postgres -c "ALTER USER power_user WITH PASSWORD '""" + postgres_power_user_pass + """';"
sudo -u postgres psql -U postgres -c "CREATE USER other_user NOSUPERUSER;"
sudo -u postgres psql -U postgres -c "ALTER USER postgres WITH PASSWORD '""" + postgres_other_user_pass + """';"
sudo -u postgres psql -U postgres -c "CREATE DATABASE snowplow WITH OWNER other_user;"
sudo -u postgres psql -U postgres -c "ALTER USER postgres WITH PASSWORD '""" + postgres_storageloader_pass + """';"

echo "Setting up database tables and schema"
wget -N https://raw.githubusercontent.com/snowplow/snowplow/master/4-storage/postgres-storage/sql/atomic-def.sql
sudo psql -U power_user -d snowplow -f atomic-def.sql

echo "Granting table and schema permissions to users"
sudo -u postgres psql -U postgres -d snowplow -c "GRANT USAGE ON SCHEMA atomic TO storageloader;"
sudo -u postgres psql -U postgres -d snowplow -c "GRANT INSERT ON TABLE "atomic"."events" TO storageloader;"
sudo -u postgres psql -U postgres -d snowplow -c "GRANT USAGE ON SCHEMA atomic TO other_user;"
sudo -u postgres psql -U postgres -d snowplow -c "GRANT SELECT ON atomic.events TO other_user;"

echo "Downloading EmrEtlRunner"
wget http://dl.bintray.com/snowplow/snowplow-generic/snowplow_emr_""" + EmrEtlVersion + """.zip

echo "Unzipping EmrEtlRunner"
unzip -o snowplow_emr_""" + EmrEtlVersion + """.zip

echo "Removing EmrEtlRunner archive"
rm snowplow_emr_""" + EmrEtlVersion + """.zip

echo "Making config directories"
mkdir config
mkdir config/targets
mkdir config/enrichments

echo "Creating EmrEtl config file"
cat > config/config.yml <<EOL """ + EmrEtlConfig + """EOL

echo "Creating Iglu resolver config"
wget -N -P config/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/iglu_resolver.json

echo "Creating storage target config"
cat > config/targets/postgres.json <<EOL """ + storage_target_config + """EOL

echo "Setting up enrichments"
wget -N -P config/enrichments/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/enrichments/anon_ip.json
wget -N -P config/enrichments/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/enrichments/campaign_attribution.json
wget -N -P config/enrichments/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/enrichments/cookie_extractor_config.json
sed -i 's/\["sp"\]/\["sp", "_ga"\]/g' config/enrichments/cookie_extractor_config.json
wget -N -P config/enrichments/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/enrichments/event_fingerprint_enrichment.json
wget -N -P config/enrichments/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/enrichments/ip_lookups.json
wget -N -P config/enrichments/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/enrichments/ua_parser_config.json
wget -N -P config/enrichments/ https://raw.githubusercontent.com/snowplow/snowplow/master/3-enrich/config/enrichments/referer_parser.json

crontab -l | grep -q '""" + start_enrich_cmd + """' && echo 'Enrichment schedule already exists' || (crontab -l ; echo "0 6 * * 1 '""" + enrichment_schedule + " " + start_enrich_cmd + """'") | crontab -

echo "EmrEtl Setup complete!"
exit
"""


# Create SSH client using the EC2 private key created earlier
key = paramiko.RSAKey.from_private_key_file('snowplow-ec2.pem')
shh_client = paramiko.SSHClient()
shh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Connect/ssh into the EC2 instance
try:
    shh_client.connect(hostname=instance_hostname, username="ec2-user", pkey=key)

    # Execute the script after connecting to the instance
    stdin, stdout, stderr = shh_client.exec_command(setup_script)
    print(stdout.read())

    # close the client connection once the job is done
    shh_client.close()

except Exception as e:
    print(e)

