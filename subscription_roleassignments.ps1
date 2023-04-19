Function Main {

    Param
	(
	
		[Parameter(Mandatory = $False)] [String] $SubscriptionName,
        	[Parameter(Mandatory = $False)] [String] $ExportPath
		
	)

    # Explaining to the user how to use this script
    Write-Host "[INFO] This script will display which roles are assigned to users in a subscription" -ForegroundColor Yellow
    Write-Host "[INFO] You'll require Read permissions on the subscription in order to view this information" -ForegroundColor Yellow
    Write-Host "[INFO] When entering an export path please make sure you include the trailing '\' like 'C:\temp\'" -ForegroundColor Yellow

    $ExportPath = Read-Host -Prompt "Where would you like to save the export to?"
    $SubscriptionName = Read-Host -Prompt "Please enter a subscription name"

    # Getting the subscriptionId based on the Name and passing on the ExportPath
    Get-SubscriptionId -SubscriptionName $SubscriptionName -ExportPath $ExportPath

}

Function Get-SubscriptionId {

    Param
	(
	
		[Parameter(Mandatory = $False)] [String] $SubscriptionName,
		[Parameter(Mandatory = $False)] [String] $Id,
		[Parameter(Mandatory = $False)] [String] $ExportPath
		
	)

    # Getting the subscriptionId
    [String]$Id = (Get-AzSubscription | Where-object {($_.Name -eq $SubscriptionName)}).Id

    # Concatenating the supplied ExportPath with the appended SubscriptionName for the .csv export
    $Path = $ExportPath + "$($SubscriptionName)_Roleassignments.csv"

    # Get the Azure Role assignment for the specified subscription to return User role assignments and exporting the results to the specified path
    Get-RoleAssignment -SubscriptionName $SubscriptionName -Id $Id |
    Select-Object DisplayName, SignInName, RoleDefinitionName, Scope, Description |
    Export-Csv -Path $Path -NoTypeInformation -Encoding utf8

    Write-Host "Results exported to $Path" -ForegroundColor Green

}

Function Get-RoleAssignment {


    Param
	(
	
		[Parameter(Mandatory = $False)] [String] $SubscriptionName,
        	[Parameter(Mandatory = $False)] [String] $Id
		
	)

    # Get the Azure Role assignment for the specified subscription to return User and Group role assignments and storing this in the $Roles variable
    $Roles = Get-AzRoleAssignment -Scope "/subscriptions/$Id" | 
    Where-Object ({$_.ObjectType -in "User", "Group"})

    # Check if there are no results
    if (!$Roles) {

        Write-Host "No results found" -ForegroundColor Red
        Exit;

    }

    # Output the results
    else {

        Write-Output $Roles
        
    }

}

Main
