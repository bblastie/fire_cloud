import requests
import argparse
import re
import json
import xml.etree.ElementTree as ET
import subprocess
import pydig
import uuid
from termcolor import colored

def service_detection(cnames):
    cloud_services = {
        "s3": [],
        "s3_open": [],
        "ec2": [],
        "cloudfront": [],
        "elb": [],
        "documentdb": [],
        "api_gateway": [],
        "elasticbeanstalk": [],
        "gcp_bucket": []
    }
    print("[+] Starting Service Detection")
    print("------------------------------------------------------------------------------------------------------------")
    s3_pattern = r'(?:(?:[a-zA-Z0-9-]+\.)+s3(?:-website-[a-z0-9-]+)?\.amazonaws\.com)'
    ec2_pattern = r'.*(ec2|compute\.amazonaws\.com).*'
    cloudfront_pattern = r'.*(cloudfront\.net).*'
    elb_pattern = r'.*(elb\.amazonaws\.com).*'
    documentdb_pattern = r'\b\w+\.docdb\.amazonaws\.com\b'
    api_gateway_pattern = r'.*(execute-api\.[A-Za-z0-9.-]+\.amazonaws\.com).*'
    elasticbeanstalk_pattern = r'.*(elasticbeanstalk\.com).*'
    gcp_bucket_pattern = r'.*(storage\.googleapis\.com).*'

    for cname in cnames:
        s3 = re.findall(s3_pattern, cname)
        ec2 = re.findall(ec2_pattern, cname)   
        cloudfront = re.findall(cloudfront_pattern, cname)
        elb = re.findall(elb_pattern, cname)
        documentdb = re.findall(documentdb_pattern, cname)
        api_gateway = re.findall(api_gateway_pattern, cname)
        elasticbeanstalk = re.findall(elasticbeanstalk_pattern, cname)
        gcp_bucket = re.findall(gcp_bucket_pattern, cname)

        if s3:
            print(colored(f"[+] AWS S3 Bucket Found: {cname}", "green"))
            cloud_services['s3'].append(cname)
        elif ec2:
            print(colored(f"[+] AWS EC2 Instance Found: {cname}", "green"))
            cloud_services['ec2'].append(cname)
        elif cloudfront:
            print(colored(f"[+] AWS Cloudfront Distribution Found: {cname}", "green"))
            cloud_services['cloudfront'].append(cname)
        elif elb:
            print(colored(f"[+] AWS ELB Found: {cname}", "green"))
            cloud_services['elb'].append(cname) 
        elif documentdb:
            print(colored(f"[+] AWS DocumentDB Found: {cname}", "green"))
            cloud_services['documentdb'].append(cname)
        elif api_gateway:
            print(colored(f"[+] AWS API Gateway Found: {cname}", "green"))
            cloud_services['api_gateway'].append(cname)
        elif elasticbeanstalk:
            print(colored(f"[+] AWS Elastic Beanstalk Found: {cname}", "green"))
            cloud_services['elasticbeanstalk'].append(cname)
        elif gcp_bucket:
            print(colored(f"[+] GCP Bucket Found: {cname}", "green"))
            cloud_services['gcp_bucket'].append(cname)
    print(f"[+] Service Detection Complete!")
    return cloud_services

def s3_bucket_public(obj):
    for bucket in obj['s3']:
        print(f"[+] Checking S3 bucket: {bucket} for public access")
        try:
            response = requests.get(f"http://{bucket}", timeout=5)
            if "ListBucketResult" in response.text:
                print(colored(f"[!] Public access is open! Adding {bucket} to list of open buckets.\n", "green"))
                print(colored("[+] Consider running this with the -u or -d flag to test upload/download of files", "yellow"))
                obj['s3_open'].append(bucket)
                print(f"[+] Listing contents of {bucket}")
                print("------------------------------------------------------------------------")
                root = ET.fromstring(response.content)
                key_elements = root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Contents/{http://s3.amazonaws.com/doc/2006-03-01/}Key")
                file_names = [key.text for key in key_elements]
                for file_name in file_names:
                    print(colored(f"[!] File found: {file_name}", "green"))
            else:
                print(colored("[!] Public access does not appear to be open.", "red"))
                print("\n")
        except requests.exceptions.Timeout:
            print("[-] Request timed out. This may be not be a public bucket.")  
            print("\n")
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] An error occurred -- Bucket may be behind Cloudfront\n", "red"))
            print(f"[!] Exception: {e}")

def s3_bucket_upload_exploit(obj):
    for bucket in obj['s3_open']:
        print(f"[+] Attempting to exploit {bucket} by uploading file")
        file = str(uuid.uuid4()) + ".txt"
        try:
            response = requests.put(f"http://{bucket}/{file}", data="test", timeout=5)
            if response.status_code == 200:
                print(colored(f"[!] Exploit successful! File {file} uploaded to bucket.", "green"))
            else:
                print("[-] Upload Exploit unsuccessful.")
        except requests.exceptions.Timeout:
            print(colored("[-] Request timed out.", "red"))  
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] An error occurred -- check {bucket} manually", "red"))

def s3_bucket_download_exploit(obj):
    for bucket in obj['s3_open']:
        bucket_files = []
        print(f"[+] Listing contents of {bucket}")
        try:
            response = requests.get(f"https://{bucket}", timeout=5)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                key_elements = root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Contents/{http://s3.amazonaws.com/doc/2006-03-01/}Key")
                file_names = [key.text for key in key_elements]
                bucket['files'] = file_names
                for file_name in file_names:
                    bucket_files.append(file_name)
                    print(colored(f"[!] File found: {file_name}", "green"))
            else:
                print(f"[-] Unable to view files, check {bucket} manually.")
            print("\n")
        except requests.exceptions.Timeout:
            print(colored("[-] Request timed out.", "red"))  
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] An error occurred -- check {obj['s3_open']} manually", "red"))

def s3_takover_exploit(obj):
    print("------------------------------------------------------------------------------------------------------------")
    print("[+] Checking S3 buckets and Cloudfront instances for S3 takeover")
    # https://hackingthe.cloud/aws/exploitation/orphaned_%20cloudfront_or_dns_takeover_via_s3/
    # This will check for the response "Bucket does not exist, which could lead to a subdomain takeover"
    # This will search known buckets and Cloudfront instances, but can be checked against any subdomain
    for bucket in obj['s3']:
        try: 
            response = requests.get(f"http://{bucket}", timeout=5)
            if "NoSuchBucket" in response.text:
                print(colored(f"[!] Bucket deleted improperly, subdomain takeover may be possible on {'domain'}!!!", "green"))
            else:
                print(f"[-] Bucket: {bucket} exists, not vulnerable")
        except requests.exceptions.Timeout:
            print(colored("[-] Request timed out.", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] An error occurred -- check {bucket} manually", "red"))
    for cloudfront in obj['cloudfront']:
        try:
            response = requests.get(f"http://{cloudfront}", timeout=5)
            if "Bucket does not exist" in response.text:
                print(colored(f"[!] Bucket deleted improperly, subdomain takeover may be possible on {cloudfront}", "green"))
            else:
                print(colored(f"[-] Instance: {cloudfront} not vulnerable", "red"))
        except requests.exceptions.Timeout:
            print("[-] Request timed out.")
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] An error occurred -- check {cloudfront} manually", "red"))

def elb_takeover(obj):
    print("------------------------------------------------------------------------------------------------------------")
    print("[+] Checking ELB instances for dangling CNAME")
    for elb in obj['elb']:
        try:
            response = requests.get(f"http://{elb}", timeout=5)
            if "NXDOMAIN" in response.text:
                print(f"[!] ELB appears to have been deleted improperly, investigate for additional impact {elb}")
            else:
                print(colored(f"[-] Instance: {elb} is not dangling", "yellow"))
                print(colored(f"[-] Response: {response.text}", "yellow"))
        except requests.exceptions.Timeout:
            print(colored(f"[-] Request timed out for {elb}.", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] An error occurred -- check {elb} manually", "red"))
            print(f"[-] Exception: {e}")

def ec2_checks(obj):
    print("------------------------------------------------------------------------------------------------------------")
    for ec2 in obj['ec2']:
        try:
            print(f"[+] nmap scanning EC2 instance: {ec2}")
            nmap_command = f"nmap -Pn -p- -sT -o {ec2}-scan {ec2}"
            ec2_nmap = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
            if ec2_nmap.returncode == 0:
                print(colored(f"[!] TCP Full Port Scan completed on {ec2}. Results saved to {ec2}-scan", "green"))
        except Exception as e:
            print(colored(f"[-] An error occurred -- check {ec2} manually", "red"))
            print(f"[-] Exception: {e}")

def beanstalk_takeover(obj):
    print("------------------------------------------------------------------------------------------------------------")
    print("[+] Checking Elastic Beanstalk instances for subdomain takeover")
    for beanstalk in obj['elasticbeanstalk']:
        try:
            response = requests.get(f"http://{beanstalk}", timeout=5)
            if "NXDOMAIN" in response.text:
                print(colored(f"[!] Beanstalk appears to have been deleted improperly, subdomain takeover may be possible on {beanstalk}", "green"))
            else:
                print(f"[-] Instance: {beanstalk} not vulnerable")
        except requests.exceptions.Timeout:
            print(colored("[-] Request timed out.", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] An error occurred -- check {beanstalk} manually", "red"))

def gcp_bucket_sniping(obj):
    print("------------------------------------------------------------------------------------------------------------")
    print("[+] Checking GCP buckets for takeover")
    for bucket in obj['gcp_bucket']:
        try:
            response = requests.get(f"http://{bucket}", timeout=5)
            if "NoSuchBucket" in response.text:
                print(colored(f"[!] GCP bucket appears vulnerable to takeover at {bucket}", "green"))
            else:
                print(f"[-] GCP bucket is not vulnerable to takeover at {bucket}")
        except requests.exceptions.Timeout:
            print(colored("[-] Request timed out.", "red"))  
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] An error occurred -- check {bucket} manually", "red"))

def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', help='file containing subdomains to check', required=True)
    parser.add_argument('-s', '--s3-download', help='enable download files from open S3 buckets', required=False, action='store_true')
    parser.add_argument('-u', '--s3-upload', help='enable upload files to open S3 buckets', required=False, action='store_true')
    parser.add_argument('-e', '--ec2', help='enable EC2 nmap scans to search for open ports', required=False, action='store_true')
    return parser.parse_args() 

def get_cname(fqdn):
    cname = pydig.query(fqdn, "CNAME")
    if len(cname) == 0:
        return None
    else:
        for c in cname:
            # strip out the trailing period
            c = c.strip(".")
            # return just string of cname instead of list, per pydig default
            cname = c
        return cname

def main(args):
    if args.file:
        with open (args.file, "r") as file:
            fqdn_list = file.readlines()
    cname_list = []
    print("[+] Starting CNAME Enumeration")
    for fqdn in fqdn_list:
        fqdn = fqdn.strip()
        cname = get_cname(fqdn)
        if cname:
            cname_list.append(cname)
    print(f"[+] CNAME Enumeration Complete!  {len(cname_list)} CNAMEs found.")
    service_object = service_detection(cname_list)
    s3_takover_exploit(service_object)
    s3_bucket_public(service_object)
    if args.s3_download:
        s3_bucket_download_exploit(service_object)
    if args.s3_upload:
        s3_bucket_upload_exploit(service_object)
    elb_takeover(service_object)
    if args.ec2:
        ec2_checks(service_object)
    beanstalk_takeover(service_object)
    gcp_bucket_sniping(service_object)
    print("------------------------------------------------------------------------------------------------------------")
    print(colored("[+] Final list of services found", "green"))
    print(json.dumps(service_object, indent=4)) 
    exit()

if __name__ == '__main__':
    args = arg_parse()
    main(args)