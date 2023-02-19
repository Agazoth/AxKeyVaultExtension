function Connect-AzVault {
    [CmdletBinding()]
    param (
        # Please make sure the AzContext is available for the current user
        [Parameter(Mandatory = $true)]
        $ContextName
    )
    
    begin {
        $InitialContext = Get-AzContext
    }
    
    process {
        if ($InitialContext.Name -ne $ContextName) {
            $RequiredContext = Get-AzContext $ContextName
            if (!$RequiredContext) {
                throw "$ContextName not found! You must be logged in to your subscription and Enable AzContext Autosave."
            }
            $SetContext = Select-AzContext -Name $ContextName
            $reset = $true
        }
        else { $reset = $false }
    }
    
    end {
        # Send the original context to the pipeline
        return [pscustomobject]@{ InitialContext = $InitialContext; Reset = $reset }
    }
}
function Get-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName
    }
    
    process {
        $secret = Get-AzKeyVaultSecret -VaultName $AdditionalParameters.KeyVaultName -Name $Name
        if ($secret){
            $s = Get-SecretObject -KeyVaultSecret $secret
            return $s
        }
    }
    
    end {
        if ($Info.Reset){
            $null = Set-AzContext $Info.InitialContext
        }
        
    }
}
function Get-SecretInfo
{
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName 
    }
    
    process {
        $pattern = [WildcardPattern]::new($Filter)
        $VaultSecrets = Get-AzKeyVaultSecret -VaultName $AdditionalParameters.KeyVaultName
        foreach ($vs in $VaultSecrets) {
            if ($pattern.IsMatch($vs.Name)) {
                $st = Get-SecretObject -KeyVaultSecret $vs -SecretInfo
                Write-Output (
                    [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                        $vs.Name,
                        $st.Value,
                        $VaultName)
                )
            }
        }
    }
    
    end {
        if ($Info.Reset){
            $null = Set-AzContext $Info.InitialContext
        }
    }
}
function Get-SecretObject {
    [CmdletBinding()]
    param (
        $KeyVaultSecret,
        [switch]$SecretInfo
    )
    
    begin {
        $ReturnInfo = @{
            Name = $KeyVaultSecret.Name
            Value = 'SecureString'
        }
    }
    
    process {
        try {
            if ($KeyVaultSecret.Tags.AxKeyVaultExtension -eq 'PSCredential'){
                $ReturnInfo['Value'] = 'PSCredential'
            }

        } catch {

        }
        if (!$SecretInfo){
            if ($ReturnInfo['Value'] -eq 'PSCredential'){
                $Json = $KeyVaultSecret.SecretValue
                | ConvertFrom-SecureString -AsPlainText
                | ConvertFrom-Json
                $ReturnInfo = [pscredential]::new($Json.UserName,$($Json.Password | ConvertTo-SecureString -AsPlainText -Force))
            } else {
                $ReturnInfo = $KeyVaultSecret.SecretValue
            }
        }
        return $ReturnInfo
    }
    
    end {
        $Json = $ReturnInfo = $null
    }
}
function Remove-Secret
{
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName
    }
    
    process {
        $Secret = Get-AzKeyVaultSecret -VaultName $AdditionalParameters.KeyVaultName -Name $Name
        if ($Secret){
            $null = Remove-AzKeyVaultSecret -VaultName $AdditionalParameters.KeyVaultName -Name $Secret.Name -Force
        }
        return $?
    }
    
    end {
        if ($Info.Reset){
            $null = Set-AzContext $Info.InitialContext
        }
    }
}
function Set-Secret
{
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName
        $Tag = @{AxKeyVaultExtension='SecureString'}
    }
    
    process {
        if ($Secret -is [String]){
            $SecretString = $Secret | ConvertTo-SecureString -AsPlainText -Force
        }
        if ($Secret -is [PSCredential]){
            $SecretString = @{
                UserName = $Secret.UserName
                Password = $Secret.GetNetworkCredential().Password
            } | ConvertTo-Json -Compress | ConvertTo-SecureString -AsPlainText -Force
            $Tag.AxKeyVaultExtension = 'PSCredential'
        }
        $null = Set-AzKeyVaultSecret -VaultName $AdditionalParameters.KeyVaultName -Name $Name -SecretValue $SecretString -Tag $Tag
        return $?
    }
    
    end {
        if ($Info.Reset){
            $null = Set-AzContext $Info.InitialContext
        }
    }
}
function Test-SecretVault
{
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    return $true
}
