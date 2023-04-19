# Azure-Scripts

This repository contains a collection of scripts I have written for information gathering within Azure.

## Dangling Dnsrecords Azure
[Dangling DNS Records](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover) are a collection of multiple issues, these issues arise when these records aren't managed properly.
Microsoft have created a tool which helps identify records that point to decommissioned resources, but what if these resources exist elsewhere?
This PowerShell script will enumerate all DNS Zones in Azure and will attempt to resolve any CNAME records that have been found.
If a record cannot be resolved, this record will be exported to a .csv file.
This script can be helpful when managing DNS records across multiple workloads.

## RBAC groups and permissions
This PowerShell script will enumerate all Azure AD Groups that have got Azure Roles assigned, but are not a [Role Assignable Group](https://learn.microsoft.com/en-us/azure/active-directory/roles/groups-create-eligible?tabs=ms-powershell).
When such groups grant any Owner, Administrator or Contributer role this could become a liability.
Quickly find out which groups exist within your tenant to help you decide whether they should be made Role Assignable, this can be very helpful when deciding how best to utilize the 500 slot limit per tenant.

## Subscription Roleassignments
This PowerShell script will enumerate direct role assignments in Azure for Users and Groups on Subscription level.
Specify the Subscription you're interested in and provide an export path, this script will then gather the data.
This can be usefull for reviews of role assignments when trying to ascertain if they are still required.
