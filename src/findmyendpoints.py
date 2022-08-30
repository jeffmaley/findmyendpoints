"""
findmyendpoints
author: jeffmaley@gmail.com

This project reports information about publicly-available
endpoints in AWS. Its focus is on Elastic Network Interfaces (ENIs).
"""

import boto3

from models.NetworkInterface import NetworkInterface

def get_boto3_session(region):
    """
    Return a boto3 session for the specified region
    
    Inputs:
        region = string
        
        
    Returns:
        boto3 session 
    """

    boto3_session = boto3.session.Session(region_name=region)
    return boto3_session

def get_boto3_client(session, service, region):
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

def get_boto3_resource(session, service, region):
    """
    Return a boto3 resource for the specified service in the specified region
    
    Inputs:
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
    return ec2.describe_regions(
        AllRegions=False
    )["Regions"]

def iter_network_interfaces(session, region) -> list:
    """
    Returns elastic network interfaces in a region
    
    Inputs:
        session = boto3 session object
        region = string

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
            response = session.describe_network_interfaces()
        else:
            response = session.describe_network_interace(
                NextToken=next_token
            )
        next_token = response.get("NextToken")
        for i in response.get("NetworkInterfaces"):
            network_interfaces.append(i)
    for network_interface in network_interfaces:
        yield network_interface

def get_network_interface_attachment(resource, id) -> list:
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

def get_instance_name(client, instance_id) -> dict:
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

def output_console(network_interfaces):
    """
    Displays final output to a console
    
    Inputs:
        network_interfaces = list of NetworkInterface

    Returns:
        None
    """
    print("Network Interface Id\tInstance Id\t\tInstance Name\tPublic Ip\tPublic DNS\t")
    for i in network_interfaces:
        print("{}\t{}\t{}\t{}\t{}".format(i.id, i.instance_id, i.instance_name, i.public_ip, i.public_dns))

def main():
    """
    Main entry point
    """
    
    network_interfaces = []
    regions = []
    regions = get_regions()
    for region in regions:
        boto3_session = get_boto3_session(region.get("RegionName"))
        print("Processing {}...".format(region.get("RegionName")))
        ec2_client = get_boto3_client(boto3_session, "ec2", region.get("RegionName"))
        for network_interface in iter_network_interfaces(ec2_client, region["RegionName"]):
            nic = NetworkInterface.NetworkInterface(id=network_interface.get("NetworkInterfaceId"))
            if network_interface.get("Association") is not None:
                nic.public_ip = network_interface.get("Association").get("PublicIp")
                nic.public_dns = network_interface.get("Association").get("PublicDnsName")
                nic.association_id = network_interface.get("Association").get("AssociationId")
                nic.allocation_id = network_interface.get("Association").get("AllocationId")
                if nic.public_ip:
                    ec2_resource = get_boto3_resource(boto3_session, "ec2", region.get("RegionName"))
                    instance_info = get_network_interface_attachment(ec2_resource, nic.id)
                    nic.instance_id = instance_info.get("InstanceId")
                    instance_tag_info = get_instance_name(ec2_client, nic.instance_id)
                    instance_tags = instance_tag_info.get("Tags")
                    nic.instance_name = instance_tags[0].get("Value")
                    network_interfaces.append(nic)
    output_console(network_interfaces)
    return

if __name__ == "__main__":
    main()