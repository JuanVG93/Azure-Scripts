Function LogonAAD {
	#Checking if there's a session active in AzureAD, if no active session then it will log you in
    Write-Host "Checking if you're currently signed into AzureAD" -Foregroundcolor Yellow
	
    if($azureConnection.Account -eq $null) 
    {
        Write-Host "You're currently not signed into AzureAD" -Foregroundcolor Red
        $AdminUser = whoami /upn
        $AzureConnection1 = Connect-AzAccount -Account $AdminUser
		$AzureConnection2 = Connect-AzureAD -AccountId $AdminUser
        $ObjectId = (Get-AzureADUser -ObjectId $AdminUser).ObjectId
        Write-Host "You are now signed into AzureAD! Welcome back $AdminUser" -Foregroundcolor Green
		
	}
		
	else {
		Write-Host "You're already signed into AzureAD!" -Foregroundcolor Green
	}
}

Function Main {
	
	try {
	
		# Cache all AAD Groups
		Write-Host "[INFO] Caching all AAD Groups..." -Foregroundcolor Yellow
		$AADGroupId = (Get-AzureADGroup -All $True).ObjectId
		
		# Get the AAD Group Name
		$AADGroupName = (Get-AzureADGroup -All $True).DisplayName
		
		# Counting all AAD Groups
		$TotalAADGroups = $AADGroupName.Count
		Write-Host "[INFO] $TotalAADGroups AAD Groups found..." -Foregroundcolor Gray
		
	}
	
	catch {
			
			Write-Host "`nError Message: " $_.Exception.Message -Foregroundcolor Red
			Write-Host "`nError Processing: " $_.Rolename -Foregroundcolor Red
			Write-Host "`nError in Line: " $_.InvocationInfo.Line -Foregroundcolor Red
			Write-Host "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber -Foregroundcolor Red
			Write-Host "`nError Item Name: "$_.Exception.ItemName -Foregroundcolor Red

	}
	
}

# Gather all the AAD groups and return whether they are role assignable or not
Function RBAC_Groups {
	
	Param
	(
	
		[Parameter(Mandatory = $False)] [array] $NotRoleAssignable
		
	)
	
	# Creating empty arrays
	$Groups = @()
	$RoleAssignable = @()
	$NotRoleAssignable = @()
	
	# Caching Role Assignable Groups
	Write-Host "[INFO] Caching all role assignable groups..." -Foregroundcolor Yellow
	$Groups = (Get-AzureADMSGroup -all $True)
	
	# Role Assignable
	$RoleAssignable = $Groups | Where-Object {($_.IsAssignableToRole -eq "True")}
	$TotalRoleAssignable = $RoleAssignable.Count
	Write-Host "[INFO] $TotalRoleAssignable Role Assignable AAD Groups found..." -Foregroundcolor Gray
	
	# Not Role Assignable
	$NotRoleAssignable = $Groups | Where-Object {($_.IsAssignableToRole -ne "True")}
	$TotalNotRoleAssignable = $NotRoleAssignable.Count
	Write-Host "[INFO] $TotalNotRoleAssignable Non Role Assignable AAD Groups found..." -Foregroundcolor Gray
	
	# Gathering Subscription Permissions
	Subscription_Permissions -NotRoleAssignable $NotRoleAssignable | Select DisplayName, RoleDefinitionName, Scope, CanDelegate | Export-CSV "C:\temp\Subscription_Permissions.csv" -NoTypeInformation -Encoding UTF8
	
}

# Gather all the permissions granted to an AAD Security Group across all Active Subscriptions
Function Subscription_Permissions {
	
	Param
	(
	
		[Parameter(Mandatory = $True)] [array] $NotRoleAssignable
		
	)
	
	# Cache all Active Subscriptions
	$SubscriptionId = (Get-AzSubscription | Where-Object {$_.State -eq "Enabled"})
	
	# Count Active Subscriptions
	$TotalSubscriptions = $SubscriptionId.Count
	Write-Host "[INFO] $TotalSubscriptions Active Subscriptions found..." -Foregroundcolor Gray
	
	# Start collecting data
	Write-Host "[INFO] Collecting Non Role Assignable Permissions..." -Foregroundcolor Yellow
	
	try {
		
		# Looping through all Active Subscription ID's
		ForEach ($ID in $SubscriptionId) {
			
			# Gather the Role Assignments and filtering on Owner, Administrator and Contributor roles
			$RoleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$ID" | 
			Where-Object {($_.ObjectId -in $NotRoleAssignable.Id -and ($_.RoleDefinitionName -like "*Owner") -or ($_.ObjectId -in $NotRoleAssignable.Id -and $_.RoleDefinitionName -like "*Administrator") -or ($_.ObjectId -in $NotRoleAssignable.Id -and$_.RoleDefinitionName -like "*Contributor"))}
			
			ForEach ($RoleAssignment in $RoleAssignments) {
				
				<# $RoleAssignment | 
				Select-Object @{ Name = "AAD Group" ; Expression = { $GroupId.Name }},
				@{ Name = "Role" ; Expression = { $GroupId.RoleDefinitionName }},
				@{ Name = "ObjectType" ; Expression = { $GroupId.ObjectType }},
				@{ Name = "CanDelegate" ; Expression = { $GroupId.CanDelegate }} #>
				
				Write-Output $RoleAssignment
			
			}
			
			
		}
		

	}
	
	catch {
			
			Write-Host "`nError Message: " $_.Exception.Message -Foregroundcolor Red
			Write-Host "`nError Processing: " $_.Rolename -Foregroundcolor Red
			Write-Host "`nError in Line: " $_.InvocationInfo.Line -Foregroundcolor Red
			Write-Host "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber -Foregroundcolor Red
			Write-Host "`nError Item Name: "$_.Exception.ItemName -Foregroundcolor Red

	}
	
	
}

LogonAAD
Main
RBAC_Groups
Write-Host "Done!" -Foregroundcolor Green
