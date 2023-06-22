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

    # This hashtable contains all known regex patterns for common secrets
    $RegexPattern = @{}

    # The following regex patterns come from https://jaimepolop.github.io/RExpository/

    #Hashed Passwords
    $RegexPattern["\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}"] = "Hashed Password Apr1 MD5"
    $RegexPattern["\{SHA\}[0-9a-zA-Z/_=]{10,}"] = "Hashed Password Apache SHA"
    $RegexPattern["\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*"] = "Hashed Password Blowfish"
    $RegexPattern["\$S\$[a-zA-Z0-9_/\.]{52}"] = "Hashed Password Drupal"
    $RegexPattern["[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}"] = "Hashed Password Joomlavbulletin"
    $RegexPattern["\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}"] = "Hashed Password Linux MD5"
    $RegexPattern["\$H\$[a-zA-Z0-9_/\.]{31}"] = "Hashed Password phpbb3"
    $RegexPattern["\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}"] = "Hashed Password sha512crypt"
    $RegexPattern["\$P\$[a-zA-Z0-9_/\.]{31}"] = "Hashed Password Wordpress"

    #Raw Hashes
    $RegexPattern["(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)"] = "Raw Hash sha512"

    #API Keys
    $RegexPattern["(atlassian[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{24})['""]"] = "Atlassian API Key"
    $RegexPattern["amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"] = "AWS MWS Key"
    $RegexPattern["aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]"] = "AWS Secret Key"
    $RegexPattern["xox[baprs]-([0-9a-zA-Z]{10,48})?"] = "Slack Token"
    $RegexPattern["gho_[0-9a-zA-Z]{36}"] = "Github Oauth Access Token"
    $RegexPattern["ghp_[0-9a-zA-Z]{36}"] = "Github Personal Access Token"
    $RegexPattern["(ghu|ghs)_[0-9a-zA-Z]{36}"] = "Github App Token"
    $RegexPattern["glpat-[0-9a-zA-Z\-]{20}"] = "Gitlab Personal Access Token"
    $RegexPattern["(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key| amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret| api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret| application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket| aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password| bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key| bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver| cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret| client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password| cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login| connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test| datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password| digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd| docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid| dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password| env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]"] = "Generic API Token"
    $RegexPattern["((bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9_\-]{64})['""])"] = "Bitbucket Client Secret"
    $RegexPattern["dapi[a-h0-9]{32}"] = "DataBricks API Key"
    $RegexPattern["AIza[0-9A-Za-z_\-]{35}"] = "Google API Key"
    $RegexPattern["[a-z0-9]{14}\.atlasv1\.[a-z0-9_=\-]{60,70}"] = "Hashicorp Terraform user/org API Key"
    $RegexPattern["<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<"] = "Jenkins Creds"
    $RegexPattern["linkedin(.{0,20})?['""][0-9a-z]{16}['""]"] = "LinkedIn Secret Key"

    # The following regex pattern was written based on https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-defn-azure-ad-client-secret?view=o365-worldwide#pattern
    $RegexPattern["['\""]([a-z0-9_\-~.]{25,40})['\""]"] = "Azure Client Secret"

    $Scripts = (Get-ChildItem $ScriptPath -Recurse -Include "*.ps1").FullName

    try {

        ForEach ($Script in $Scripts) {

            foreach ($Key in $RegexPattern.Keys) {

                # This variable keeps track of the line number where the potential secret is exposed
                $LineNumber = 0

                # Reach each script line by line
                $Found = @(ForEach ($Line in Get-Content $Script) {

                    # Keep track of which linenumber is currently being read
                    $LineNumber++

                    # Check if the line matches the supplied RegEx patterns
                    if ($Line -match $Key) {

                        # A match has been found
                        $MatchedString = $RegexPattern[$Key]

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
                            SecretType = ($MatchedString).Trim()
                            LineNumber = ($LineNumber | Out-String).Trim()
                            PotentialSecret = ($Line | Out-String).Trim()

                        }

                    }

                })

            }


            # Output the array
            if ($Found) {

                Write-Output $Output |
                Select-Object Workload, AutomationAccountName, ResourceGroupName, AzureRunbook, SecretType, LineNumber, PotentialSecret

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
    
    Main

}
