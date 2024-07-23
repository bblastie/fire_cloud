# fire_cloud
This is a basic enumeration script to identify AWS Cloud Resources by taking in a list of subdomains (such as from Amass or subfinder) and check their DNS record for CNAME records pointing to an AWS resource. 

Some services, like S3, have some quick basic checks to help move along your recon against cloud facing assets. 

## Install requirements
`pip install -r requirements.txt`

## Usage
`python3 fire-cloud.py -f {file-of-subdomains}` 

## Optional params
`-e` - will perform an nmap scan against any detected EC2 instances and save output in the current directory

`-s` - will download any files stored on an S3 bucket that is open **Use with caution** 

`-u` - will try to upload a file with a random UUID name to detected buckets 

## Disclosure
I am NOT responsible for damage caused by use of this tool, make sure you understand what you're doing and what this script does. 