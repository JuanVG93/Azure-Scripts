# Azure-Scripts

This repository contains a collection of scripts I have written for information gathering within Azure.

## Dangling Dnsrecords Azure

### What does it do?
[Dangling DNS Records](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover) are a collection of multiple issues, these issues arise when these records aren't managed properly.
Microsoft have created a tool which helps identify records that point to decommissioned resources, but what if these resources exist elsewhere?
This PowerShell script will enumerate all DNS Zones in Azure and will attempt to resolve any CNAME records that have been found.
If a record cannot be resolved, this record will be exported to a .csv file.
This script can be helpful when managing DNS records across multiple workloads.

### How do I run this?
1. Clone this repo
2. Log into Azure AD through PowerShell
3. Run this script

---

## RBAC groups and permissions

### What does it do?
This PowerShell script will enumerate all Azure AD Groups that have got Azure Roles assigned, but are not a [Role Assignable Group](https://learn.microsoft.com/en-us/azure/active-directory/roles/groups-create-eligible?tabs=ms-powershell).
When such groups grant any Owner, Administrator or Contributer role this could become a liability.
Quickly find out which groups exist within your tenant to help you decide whether they should be made Role Assignable, this can be very helpful when deciding how best to utilize the 500 slot limit per tenant.

### How do I run this?
1. Clone this repo
2. Log into Azure AD through PowerShell
3. Run this script

---

## Subscription Roleassignments

### What does it do?
This PowerShell script will enumerate direct role assignments in Azure for Users and Groups on Subscription level.
Specify the Subscription you're interested in and provide an export path, this script will then gather the data.
This can be usefull for reviews of role assignments when trying to ascertain if they are still required.

### How do I run this?
1. Clone this repo
2. Log into Azure AD through PowerShell
3. Run this script
4. Supply the information when prompted

---

## Enumerate secrets from Azure Runbooks

### What does it do?
This PowerShell script will export all "Published" and "In Edit" PowerShell Runbooks across all active Subscriptions to local storage.
It will then read each runbook line by line to look for potentially exposed Client Secrets.
This can be useful for DevSecOps teams.

### How do I run this?
1. Clone this repo
2. Log into Azure AD through PowerShell
3. Run this script
4. Supply the information when prompted
