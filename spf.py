from __future__ import print_function
import sys
import re
import json
from socket import gethostbyname, gaierror
import click
from ipwhois.net import Net
from ipwhois.asn import IPASN
import logging
import dns.resolver

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

__author__ = "Bharath(github.com/yamakira)"
__modify__= "WAIDA/ninjax/"
__version__ = "0.0.1"
__purpose__ = '''Extract domains/netblocks for a SPF record'''

logger = logging.getLogger('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_spf_record(domain):
    try:
        response = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        logger.info("[+] Couldn't resolve the domain {}".format(domain))
        sys.exit(1)

    spf_record = None
    for answer in response:
        for record in answer.strings:
            record_str = record.decode('utf-8')  # Decode bytes to string
            if 'spf1' in record_str:
                spf_record = record_str

    if spf_record is not None:
        return spf_record

    logger.info("[+] {} doesn't support SPF record ".format(domain))
    sys.exit(1)


def get_assets(spf_record):
    assets = []
    spf_values = spf_record.split(" ")
    mechanisms = ['ip4:', 'ip6:', 'ptr:', 'include:', 'a:', 'include:', 'mx:', 'exists:']
    
    for item in spf_values:
        if any(mechanism in item for mechanism in mechanisms):
            assets.append(item)

    return assets

def enumerate_asn(assets):
    assets_report = {}
    mechanisms = ['ip4:', 'ip6:', 'ptr:', 'include:', 'a:', 'include:', 'mx:', 'exists:']
    
    for asset in assets:
        if asset.startswith(('ip4:', 'ip6:')):
            cidr_value = re.sub(r'|'.join(map(re.escape, mechanisms)), '', asset)
            ip_address = cidr_value.split("/")[0]
            asn_details = get_asn(ip_address)
            assets_report[ip_address] = asn_details
        elif asset.startswith('include:'):
            domain = re.sub(r'|'.join(map(re.escape, mechanisms)), '', asset)
            
            try:
                ip_address = gethostbyname(domain)
                asn_details = get_asn(ip_address)
                assets_report[domain] = asn_details
            except gaierror as e:
                assets_report[domain] = "No valid A record exists"

    return assets_report

def get_asn(ip_address):
    net = Net(ip_address)
    obj = IPASN(net)
    asn_details = obj.lookup()
    return asn_details

def print_assets(assets):
    mechanisms = ['ip4:', 'ip6:', 'ptr:', 'include:', 'a:', 'include:', 'mx:', 'exists:']
    
    for asset in assets:
        asset = re.sub(r'|'.join(map(re.escape, mechanisms)), '', asset)
        print(asset)

@click.command()
@click.argument('domain')
@click.option('--asn/--no-asn', '-a', default=False, help='Enable/Disable ASN enumeration')
def main(domain, asn):
    spf_record = get_spf_record(domain)
    assets = get_assets(spf_record)

    if asn:
        assets_reports = enumerate_asn(assets)
        print(json.dumps(assets_reports, default=str))
    else:
        print_assets(assets)

if __name__ == '__main__':
    main()
