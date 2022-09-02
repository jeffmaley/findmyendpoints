"""
findmyendpoints
author: jeffmaley@gmail.com

This project reports information about publicly-available
endpoints in AWS. Its focus is on Elastic Network Interfaces (ENIs).
"""

import datetime
import logging
import boto3
import argparse

from models import NetworkInterface
from models import bcolors

logging.basicConfig(filename="FindMyEndpoints.log",
                    format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.WARN)


def parse_arguments() -> dict:
    parser = argparse.ArgumentParser(
             description="Find public endpoinds in AWS")
    parser.add_argument("--loglevel",
                        help="Set logging level")
    parser.add_argument("--console", action="store_const", const=True,
                        help="Write output to console.")
    parser.add_argument("--csv", action="store_const", const=True,
                        help="Write output to file.")
    parser.add_argument("--filename",
                        help="Output filename. Default is FindMyEndpoints-output-[date].csv")  # noqa: E501
    parser.add_argument("--organization", action="store_const", const=True,
                        help="Check all accounts in an Organization")
    parser.add_argument("--controltower", action="store_const", const=True,
                        help="Use AWSControlExecution as destination role name")  # noqa: E501
    parser.add_argument("--rolename", default="OrganizationAccountAccessRole",
                        help="Name of the role to assume in Organization accounts")  # noqa: E501
    parser.add_argument("--default-region",
                        help="Default region for role assumption. Default is us-east-1.")  # noqa: E501
    return parser.parse_args()


def get_boto3_session(region: str,
                      aws_access_key_id=None,
                      aws_secret_access_key=None,
                      aws_session_token=None) -> boto3.Session:
    """
    Return a boto3 session for the specified region

    Inputs:
        region = string
        aws_access_key_id = string
        aws_secret_access_key = string
        aws_session_token = string

    Returns:
        boto3 session
    """

    try:
        boto3_session = boto3.session.Session(region_name=region,
                        aws_access_key_id=aws_access_key_id,  # noqa: E128
                        aws_secret_access_key=aws_secret_access_key,  # noqa: E128, E501
                        aws_session_token=aws_session_token)  # noqa: E128
        return boto3_session
    except Exception as e:
        logging.error(e)
    return None


def get_boto3_client(session: str, service: str, region: str):
    """
    Return a boto3 client for the specified service in the specified region

    Inputs:
        service = string
        region = string


    Returns:
        boto3 client object
    """

    boto3_client = session.client(service, region_name=region)
    return boto3_client


def get_boto3_resource(session: boto3.Session, service: str, region: str):
    """
    Return a boto3 resource for the specified service in the specified region

    Inputs:
        session = boto3 session
        service = string
        region = string


    Returns:
        boto3 resource object
    """

    boto3_resource = session.resource(service, region_name=region)
    return boto3_resource


def get_regions() -> list:
    """
    Returns of AWS regions

    Inputs:
        None

    Returns:
        [
            {
                'Endpoint': 'string',
                'RegionName': 'string',
                'OptInStatus': 'string'
            },
        ]
    """

    ec2 = boto3.client("ec2")
    regions_raw = ec2.describe_regions(
        AllRegions=False
    )["Regions"]
    regions = []
    for i in regions_raw:
        regions.append(i.get("RegionName"))
    return regions


def process_accounts(regions: list,
                     account_id: str,
                     credentials=None,
                     default_region=None) -> dict:
    """
    Wrapper for processing accounts

    Inputs:
        regions = list
        account_id = string
        credentials = dict
        default_region = string

    Returns:
        {
            region: [
                NetworkInterface,
                ...
                ]
        }
    """
    network_interfaces = {}
    if credentials is not None:
        boto3_session = get_boto3_session(default_region,
                        aws_access_key_id=credentials.get("AccessKeyId"),   # noqa: E501, E128
                        aws_secret_access_key=credentials.get("SecretAccessKey"),  # noqa: E501, E128
                        aws_session_token=credentials.get("SessionToken"))   # noqa: E501, E128
    else:
        boto3_session = get_boto3_session(default_region)

    if boto3_session is not None:
        for region in regions:
            ec2_client = get_boto3_client(boto3_session, "ec2", region)
            for nic in process_network_interfaces(boto3_session,
                                                  ec2_client,
                                                  region,
                                                  account_id):
                if not network_interfaces.get(nic.region):
                    network_interfaces[nic.region] = [nic]
                else:
                    network_interfaces[nic.region].append(nic)
        return network_interfaces
    else:
        logging.error("Boto3 Session missing.")
        exit(1)


def process_network_interfaces(boto3_session: boto3.Session,
                               ec2_client, region: str,
                               account_id: str):
    """
    Wrapper for network interface processing

    Inputs:
        boto3_session = boto3 Session
        ec2_client = boto3 ec2 client
        region = string
        account_id = str

    Returns:
        yields NetworkInterface
    """

    for network_interface in iter_network_interfaces(
                                    ec2_client):
        nic = NetworkInterface.NetworkInterface(
                                id=network_interface
                                .get("NetworkInterfaceId"))
        if network_interface.get("Association") is not None:
            nic.public_ip = network_interface \
                            .get("Association").get("PublicIp")
            nic.public_dns = network_interface \
                             .get("Association") \
                             .get("PublicDnsName")
            nic.association_id = network_interface \
                                 .get("Association") \
                                 .get("AssociationId")
            nic.allocation_id = network_interface \
                                .get("Association") \
                                .get("AllocationId")
            nic.region = region
            if nic.public_ip:
                ec2_resource = get_boto3_resource(
                                    boto3_session,
                                    "ec2",
                                    region)
                instance_info = get_network_interface_attachment(
                                    ec2_resource,
                                    nic.id)
                nic.instance_id = instance_info.get("InstanceId")
                instance_tag_info = get_instance_name(
                                        ec2_client,
                                        nic.instance_id)
                instance_tags = instance_tag_info.get("Tags")
                nic.instance_name = instance_tags[0].get("Value")
                nic.account_id = account_id
                yield nic


def iter_network_interfaces(ec2_client) -> list:
    """
    Returns elastic network interfaces in a region

    Inputs:
        session = boto3 session object

    Returns:
    [
        {
            'Association': {
                'AllocationId': 'string',
                'AssociationId': 'string',
                'IpOwnerId': 'string',
                'PublicDnsName': 'string',
                'PublicIp': 'string',
                'CustomerOwnedIp': 'string',
                'CarrierIp': 'string'
            },
            'NetworkInterfaceId': 'string',
            ...,
},
    ]

    """

    next_token = "X"
    network_interfaces = []
    while next_token is not None:
        if next_token == "X":
            response = ec2_client.describe_network_interfaces()
        else:
            response = ec2_client.describe_network_interace(
                NextToken=next_token
            )
        next_token = response.get("NextToken")
        for i in response.get("NetworkInterfaces"):
            network_interfaces.append(i)
    for network_interface in network_interfaces:
        yield network_interface


def get_network_interface_attachment(resource, id: str) -> list:
    """
    Returns attachment information for a boto3 NetworkInterface

    Inputs:
        resource = boto3 resource object
        id = string

    Returns:
        [
            ...,
            "InstanceId": instance_id,
            ...,
        ]

    """

    network_interface = resource.NetworkInterface(id)
    return network_interface.attachment


def get_instance_name(client, instance_id: str) -> dict:
    """
    Returns the Name tag for an instance

    Inputs:
        client = boto3 client
        instance_id = string

    Returns:
        {
            'NextToken': 'string',
            'Tags': [
                {
                    'Key': 'string',
                    'ResourceId': 'string',
                    'ResourceType': '...',
                    'Value': 'string'
                },
            ]
        }

        """

    return client.describe_tags(
        Filters=[
            {
                "Name": "resource-id",
                "Values": [
                    instance_id
                ]
            },
            {
                "Name": "key",
                "Values": [
                    "Name"
                ]
            }
        ]
    )


def get_organization_accounts():
    """
    Returns list of accounts in the AWS Organization

    Inputs:
        None

    Returns:
        list of string
    """
    org_client = boto3.client("organizations", "us-east-1")
    accounts = []
    response = org_client.list_accounts().get("Accounts")
    for account in response:
        accounts.append(account.get("Id"))
    management_account = org_client.describe_organization() \
                .get("Organization") \
                .get("MasterAccountId")
    return (accounts, management_account)


def assume_role_in_org_account(session: boto3.Session,
                               region: str,
                               account_id: str,
                               role_name: str):
    """
    Returns a boto3 session in the destination account

    Inputs:
        session = boto3 session
        region = str
        account_id=  str
        role_name = str

    Returns:
        boto3 session object
    """
    sts_client = get_boto3_client(session, "sts", region)
    credentials = {}
    try:
        response = sts_client.assume_role(
            RoleArn="arn:aws:iam::{}:role/{}"
            .format(account_id, role_name),
            RoleSessionName="FindMyEndpoints"
        )
        credentials["AccessKeyId"] = response \
                            .get("Credentials") \
                            .get("AccessKeyId")
        credentials["SecretAccessKey"] = response \
                            .get("Credentials") \
                            .get("SecretAccessKey")
        credentials["SessionToken"] = response \
                            .get("Credentials") \
                            .get("SessionToken")
    except Exception as e:
        credentials = None
        logging.error(e)
    return credentials


def output_console(network_interfaces):
    """
    Displays final output to a console

    Inputs:
        network_interfaces = list of NetworkInterface

    Returns:
        None
    """

    for account_id in network_interfaces.keys():
        print("{}\n\n{}{}".format(bcolors.bcolors.BLUE,
                                  account_id,
                                  bcolors.bcolors.DEFAULT))
        for region in network_interfaces.get(account_id).keys():
            if len(network_interfaces.get(account_id).get(region)) > 0:
                for i in network_interfaces.get(account_id).get(region):
                    print("{}\n{}{}".format(bcolors.bcolors.YELLOW,
                                            region,
                                            bcolors.bcolors.DEFAULT))
                    print("{}Network Interface Id\tInstance Id\t\tInstance Name\tPublic Ip\tPublic DNS{}"  # noqa: E501
                          .format(bcolors.bcolors.LIGHTGRAY,
                          bcolors.bcolors.DEFAULT))
                    if i.region == region:
                        print("{}\t{}\t{}\t{}\t{}".format(
                            i.id,
                            i.instance_id,
                            i.instance_name,
                            i.public_ip,
                            i.public_dns))


def output_csv(network_interfaces, filename=None):
    """
    Writes output to a csv

    Inputs:
        network_interfaces = list of NetworkInterface

    Returns:
        None
    """
    time_stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    if filename is not None:
        output_filename = filename
    else:
        output_filename = "FindMyEndpoints-output-{}.csv".format(time_stamp)
    try:
        f = open(output_filename, "w")
        f.write("Account Id,Network Interface Id,Instance Id,Instance Name,Public Ip,Public DNS,Region\n")  # noqa: E501
        for account_id in network_interfaces.keys():
            for region in network_interfaces.get(account_id).keys():
                if len(network_interfaces.get(account_id).get(region)) > 0:
                    for i in network_interfaces.get(account_id).get(region):
                        if i.region == region:
                            f.write("{},{},{},{},{},{},{}\n".format(
                                account_id,
                                i.id,
                                i.instance_id,
                                i.instance_name,
                                i.public_ip,
                                i.public_dns,
                                i.region))
        f.close()
    except Exception as e:
        logging.error(e)


def main():
    """
    Main entry point
    """
    args = parse_arguments()
    if vars(args).get("loglevel"):
        loglevel = vars(args).get("loglevel")
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logging.basicConfig(level=numeric_level)
    if vars(args).get("filename"):
        filename = vars(args).get("filename")
    else:
        filename = None
    regions = []
    regions = get_regions()
    if vars(args).get("default-region"):
        default_region = vars(args).get("default-region")
    else:
        default_region = "us-east-1"
    accounts = []
    if vars(args).get("organization"):
        (accounts, management_account) = get_organization_accounts()
        if vars(args).get("controltower"):
            role_name = "AWSControlTowerExecution"
        else:
            role_name = vars(args).get("rolename")
    network_interfaces = {}
    if len(accounts) > 0:
        for account_id in accounts:
            if account_id != management_account:
                mgmt_account_session = get_boto3_session("us-east-1")
                if mgmt_account_session is None:
                    logging.error("Unable to get boto3 session in management account.")  # noqa: E501
                    exit(1)
                credentials = assume_role_in_org_account(mgmt_account_session,
                                                         "us-east-1", account_id, role_name)  # noqa: E501
                if credentials is None:
                    logging.error("Unable to assume role in account")
                    exit(1)
                network_interfaces[account_id] = process_accounts(regions,
                                                                  account_id,
                                                                  credentials=credentials,  # noqa: E501
                                                                  default_region=default_region)  # noqa: E501
            else:
                network_interfaces[account_id] = process_accounts(regions, account_id)  # noqa: E501
    else:
        sts_client = boto3.client("sts")
        account_id = sts_client.get_caller_identity().get("Account")
        network_interfaces[account_id] = process_accounts(regions, account_id)
    if vars(args).get("console"):
        output_console(network_interfaces)
    if vars(args).get("csv"):
        output_csv(network_interfaces, filename=filename)
    return


if __name__ == "__main__":
    main()
