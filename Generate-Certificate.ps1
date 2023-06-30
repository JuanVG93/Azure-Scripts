Function New-Certificate {

    Try {

        # Load the assembly System.Web
        add-type -AssemblyName System.Web

        # Generate a random password using the System.Web assembly
        $RandomPassword = [system.web.security.membership]::GeneratePassword(12,3)

        # Display the password for the user so that the certificate can be installed
        Write-Host "Your random password: $($RandomPassword)" -ForegroundColor Green

    }

    # Error handling
    catch {

        Write-Host "`nError Message: " $_.Exception.Message -ForegroundColor Red
        Write-Host "`nError in Line: " $_.InvocationInfo.Line -ForegroundColor Red
        Write-Host "`nError in Line Number: "$_.InvocationInfo.ScriptLineNumber -ForegroundColor Red
        Write-Host "`nError Item Name: "$_.Exception.ItemName -ForegroundColor Red

    }
    
    # Prompt the user for a common name
    $commonName = Read-Host "Enter a common name"

    # The certfile name without extension should be the same as commonName
    $certFileNameWithoutExtension = $commonName

    # Generate the certificate files
    New-PnPAzureCertificate -CommonName $commonName -OutPfx "c:\temp\$certFileNameWithoutExtension.pfx" -OutCert "c:\temp\$certFileNameWithoutExtension.cer" -CertificatePassword (ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force)

}

Write-Host "[INFO] This script will generate a random password and create a self-signed certificate" -ForegroundColor Yellow
New-Certificate
Remove-Variable -Name * -ErrorAction SilentlyContinue
