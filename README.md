# FindMyEndpoints

## Description

This tool will find and display information about public endpoints in an AWS
 account. Its focus is in Elastic Network Interfaces (ENIs), which can be
 attached resources like EC2 instances and RDS DB instances.

 For AWS Organizations, this tool will use the OrganizationAccountAccessRole or
 AWSControlTowerExecution role to process member accounts and it must be run from
 the Management account.

## Installation

pip install findmyendpoints

## Usage

python -m findmyendpoints [-h]

python3 -m findmyendpoints [-h]

## TODO

* Add support for getting information on RDS and Redshift endpoints
* Add support for reading Security Group/NACLs
