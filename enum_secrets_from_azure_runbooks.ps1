Function Get-SubscriptionIds {

    Param
    (

        [Parameter(Mandatory = $False)] [String]$SubscriptionName

    )

    # Cache all Active Subscriptions
	$SubscriptionIds = (Get-AzSubscription | Where-Object {$_.State -eq "Enabled"})

    # Count Active Subscriptions
	$TotalSubscriptions = $SubscriptionIds.Count
	Write-Host "[INFO] $TotalSubscriptions Active Subscriptions found..." -Foregroundcolor Gray

    try {

        # Start looping through all subscription IDs
        ForEach ($ID in $SubscriptionIds.Id) {

            # Get the name of the Subscription
            $SubscriptionName = (Get-AzSubscription -SubscriptionId $ID).Name

            # Set the Context to the current SubscriptionID we're looping through
            Write-Host "`n[INFO] Searching through subscription: $SubscriptionName" -ForegroundColor Gray
            $SubscriptionContext = Set-AzContext -SubscriptionId $ID 2>$null

            # Gathering all Resource Groups within the current Subscription
            Get-AzureResourceGroupNames -SubscriptionName $SubscriptionName

        }

    }

    catch {

        Write-Host "`nError Message: " $_.Exception.Message -ForegroundColor Red
		Write-Host "`nError in Line: " $_.InvocationInfo.Line -ForegroundColor Red
		Write-Host "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber -ForegroundColor Red
		Write-Host "`nError Item Name: "$_.Exception.ItemName -ForegroundColor Red

    }

}

Function Get-AzureResourceGroupNames {

    Param 
    (

        [Parameter(Mandatory = $False)] [Array]$ResourceGroupNames,
        [Parameter(Mandatory = $False)] [String]$SubscriptionName
        

    )

    # Start with an empty arraylist
    [Array]$ResourceGroupNames = @()

    # Cache all ResourceGroupNames in Azure ensuring no duplicates are returned
    $ResourceGroupNames = (Get-AzResource | Select-Object ResourceGroupName | Sort-Object -Property ResourceGroupName -Unique).ResourceGroupName

    try {

        Get-AzureAutomationAccounts -ResourceGroupNames $ResourceGroupNames -SubscriptionName $SubscriptionName

    }

    catch {

        Write-Host "`nError Message: " $_.Exception.Message -ForegroundColor Red
        Write-Host "`nError in Line: " $_.InvocationInfo.Line -ForegroundColor Red
        Write-Host "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber -ForegroundColor Red
        Write-Host "`nError Item Name: "$_.Exception.ItemName -ForegroundColor Red

    }        

}

Function Get-AzureAutomationAccounts {

    Param 
    (
    
        [Parameter(Mandatory = $False)] [Array]$ResourceGroupNames,
        [Parameter(Mandatory = $False)] [String]$ResourceGroupName,
        [Parameter(Mandatory = $False)] [Array]$AutomationAccountNames,
        [Parameter(Mandatory = $False)] [String]$SubscriptionName

    )

    ForEach ($ResourceGroupName in $ResourceGroupNames) {

        try {

            # Gather the automation account for the current Resource Group
            $AutomationAccountNames = (Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName).AutomationAccountName 2>$null
            
            If ($AutomationAccountNames) {

                # Gather the Azure Runbooks written in PowerShell
                Get-AzurePowershellRunbooks -ResourceGroupName $ResourceGroupName -AutomationAccountNames $AutomationAccountNames -SubscriptionName $SubscriptionName

            }

        }

        catch {

            Write-Host "`nError Message: " $_.Exception.Message -ForegroundColor Red
            Write-Host "`nError in Line: " $_.InvocationInfo.Line -ForegroundColor Red
            Write-Host "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber -ForegroundColor Red
            Write-Host "`nError Item Name: "$_.Exception.ItemName -ForegroundColor Red
    
        }

    }

}

Function Get-AzurePowershellRunbooks {

    Param 
    (
    
        [Parameter(Mandatory = $False)] [Array]$AzureRunbooks,
        [Parameter(Mandatory = $False)] [Array]$AutomationAccountNames,
        [Parameter(Mandatory = $False)] [String]$ResourceGroupName,
        [Parameter(Mandatory = $False)] [String]$AzureRunbook,
        [Parameter(Mandatory = $False)] [String]$SubscriptionName


    )

    # First create an empty array
    $AzureRunbooks = @()

    # Gather all Azure Runbooks written in PowerShell and have been Published under the Automation Account
    ForEach ($AutomationAccountName in $AutomationAccountNames) {

        $AzureRunbooks = (Get-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName | 
        Where-Object {($_.RunbookType -eq "PowerShell") -and ($_.State -in "Published", "In edit")}).Name

        ForEach ($AzureRunbook in $AzureRunbooks) {

            Write-Host "[INFO] Exporting Azure Runbook: $($AzureRunbook)" -ForegroundColor Yellow
            Export-AzureRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -AzureRunbook $AzureRunbook -SubscriptionName $SubscriptionName

        }

    }
    
}

Function Export-AzureRunbook {

    Param 
    (

        [Parameter(Mandatory = $False)] [String]$AutomationAccountName,
        [Parameter(Mandatory = $False)] [String]$ResourceGroupName,
        [Parameter(Mandatory = $False)] [String]$AzureRunbook,
        [Parameter(Mandatory = $False)] [String]$SubscriptionName


    )

    $RunbooksPath = "C:\temp\Azure Runbooks\$($SubscriptionName)\$($AutomationAccountName)\$($ResourceGroupName)"

    if (Test-Path $RunbooksPath) {

        Export-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureRunbook -Slot "Published" -OutputFolder $RunbooksPath

    }

    else {

        New-Item -Path $RunbooksPath -ItemType Directory 2>$null
        Export-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureRunbook -Slot "Published" -OutputFolder $RunbooksPath

    } 

}

Function Get-SecretsFromRunbook {

    # Output array
    $Output = @()

    # The path where all the Azure Runbooks are stored in a separate folder for each Resource Group
    $ScriptPath = "C:\temp\Azure Runbooks"

    # This is the regex pattern for Azure AD Secrets documented on https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-defn-azure-ad-client-secret?view=o365-worldwide#pattern
    $RegexPattern = "['\""]([a-z0-9_\-~.]{25,40})['\""]"
    # This is a regex pattern array for excluding certain strings such as tenantid/objectid
    $ExcludeRegexPattern = @(

        "['\""][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\""]"

    )

    $Scripts = (Get-ChildItem $ScriptPath -Recurse -Include "*.ps1").FullName

    try {

        ForEach ($Script in $Scripts) {

            # This variable keeps track of the line number where the potential secret is exposed
            $LineNumber = 0

            # Reach each script line by line
            $Found = @(ForEach ($Line in Get-Content $Script) {
    
                # Keep track of which linenumber is currently being read
                $LineNumber++
    
                # Check if the line matches the supplied RegEx patterns
                if ($Line -cnotmatch $ExcludeRegexPattern -and $Line -match $RegexPattern) {

                    # Split all folders so that we can assign separate variables
                    $Folders = Split-Path -Path $Script -Parent

                    # AzureRunBook excluding .ps1
                    $AzureRunbook = Split-Path -Path $Script -Leaf
                    
                    # Get the Azure Runbook name
                    $Subfolders = $Script.Split("\") | Select-Object -skip 2

                    # Take the Azure Runbook name and remove the extension
                    $AzureRunbook = [System.IO.Path]::GetFileNameWithoutExtension($Script)
    
                    # Create a new array called Output and add the below properties
                    $Output += New-object PSObject -property @{
                    
                        Workload = ($Subfolders[1] | Out-String).Trim()
                        AutomationAccountName = ($Subfolders[2] | Out-String).Trim()
                        ResourceGroupName = ($Subfolders[3]| Out-String).Trim()
                        AzureRunbook = ($AzureRunbook | Out-String).Trim()
                        PotentialSecret = ($Line | Out-String).Trim()
                        LineNumber = ($LineNumber | Out-String).Trim()
    
                    }
    
                }
            })

            # Output the array
            if ($?) {

                Write-Output $Output |
                Select-Object Workload, AutomationAccountName, ResourceGroupName, AzureRunbook, LineNumber, PotentialSecret

            }

            # Remove unneeded files
            else {

                Write-Host "[INFO] No matches found for the supplied RegEx pattern, deleting $($Script)" -ForegroundColor Yellow
                Remove-Item $Script
                Write-Host "[INFO] $Script deleted" -ForegroundColor Red

            }
    
        }

        Write-Host "[INFO] Cleaning up files" -ForegroundColor Yellow
        Remove-Item -Path $ScriptPath -Recurse
        
    }

    catch {

        Write-Host "`nError Message: " $_.Exception.Message -ForegroundColor Red
        Write-Host "`nError in Line: " $_.InvocationInfo.Line -ForegroundColor Red
        Write-Host "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber -ForegroundColor Red
        Write-Host "`nError Item Name: "$_.Exception.ItemName -ForegroundColor Red

    }

}


Function Main {

    Write-Host "[INFO] This PowerShell script will attempt to enumerate Azure AD Client Secrets from Azure Runbooks across all active subscriptions" -ForegroundColor Yellow
    Write-Host "[INFO] No Key Vaults will be accessed!" -ForegroundColor Yellow

    # Cycling through subscriptionId's
    Get-SubscriptionIds

    Write-Host "`n==========================================================="
    Write-Host "`n[INFO] Finished downloading all Azure Runbooks!" -ForegroundColor Green

    # Searching for potential secrets in Azure Runbooks
    Write-Host "[INFO] Searching for potential secrets in all Azure Runbooks" -ForegroundColor Yellow
    Get-SecretsFromRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -AzureRunbook $AzureRunbook -SubscriptionName $SubscriptionName |
    Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
    Write-Host "`n[INFO] Finished checking all Azure Runbooks!" -ForegroundColor Green

    Write-Host "[INFO] File written to $Path" -ForegroundColor Yellow
    Write-Host "[INFO] Please review the report as this may contain false positives" -ForegroundColor Yellow
    Write-Host "[INFO] Script finished" -ForegroundColor Green


}

# Command Line argument to supply the path where the report needs to be saved to
$Path = $args[0]

# Check to ensure the argument is supplied
if ($Path -eq $null) {

    throw [System.ArgumentException] "You have not supplied a path where you want the report to be saved!`nCall the script again and include the full UNC path in single quotes"

}

# Only run the script if the argument is supplied
else {

    $Path = $Path + "\potentially_leaked_secrets_in_azurerunbooks.csv"

    LogonAAD
    Main

}
