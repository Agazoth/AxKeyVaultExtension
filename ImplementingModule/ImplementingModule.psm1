function Connect-AzVault {
    [CmdletBinding()]
    param (
        # Please make sure the AzContext is available for the current user
        [Parameter(Mandatory = $true)]
        $ContextName,
        [Parameter(Mandatory = $true)]
        $VaultName
    )
    
    begin {
        $InitialContext = Get-AzContext        
    }
    
    process {
        if ($InitialContext.Name -ne $ContextName) {
            $RequiredContext = Get-AzContext $ContextName
            if (!$RequiredContext) {
                throw "$ContextName not found! You must be logged in to your subscription."
            }
            $SetContext = Set-AzContext $RequiredContext
            $reset = $true
        }
        else { $reset = $false }
    }
    
    end {
        # Send the original context to the pipeline
        return [pscustomobject]@{VaultName = $VaultName; InitialContext = $InitialContext; Reset = $reset }
    }
}

function Set-Secret
{
    param (
        [string] $Name,
        [object] $Secret,
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName -VaultName $AdditionalParameters.VaultName
    }
    
    process {
        if ($Secret -is [String]){
            $Secret = $Secret | ConvertTo-SecureString -AsPlainText -Force
        }
        if ($Secret -is [PSCredential]){
            $Name = '--AxPSC--{0}--{1}' -f $Name, $Secret.UserName
            $Secret = $Secret.Password
        }
        $null = Set-AzKeyVaultSecret -VaultName $Info.VaultName -Name $Name -SecretValue $Secret
        return $?
    }
    
    end {
        if ($Info.Reset){
            $null = Set-AzContext $Info.InitialContext
        }
    }
}

function Get-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName -VaultName $AdditionalParameters.VaultName
    }
    
    process {
        $secret = Get-AzKeyVaultSecret -VaultName $Info.VaultName -Name $Name
        if ($secret){
            return $secret.SecretValue
        }
        else {
            $AxPS = '--AxPSC--{0}--' -f $Name
            $Secret = Get-AzKeyVaultSecret -VaultName $AdditionalParameters.VaultName | Where-Object {$_.Name -match "^$AxPS"} | Select-Object -first 1
            if ($Secret){
                $Secret = Get-AzKeyVaultSecret -VaultName $AdditionalParameters.VaultName -Name $Secret.Name
                return [pscredential]::new(($Secret.Name -replace $AxPS),$Secret.SecretValue)
            }
        }
    }
    
    end {
        if ($Info.Reset){
            $null = Set-AzContext $Info.InitialContext
        }
        
    }
}

function Remove-Secret
{
    param (
        [string] $Name,
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName -VaultName $AdditionalParameters.VaultName
    }
    
    process {
        $Secret = Get-AzKeyVaultSecret -VaultName $Info.VaultName -Name $Name
        if (!$Secret){
            $Secret = Get-AzKeyVaultSecret -VaultName $Info.VaultName | Where-Object {$_.Name -match $('^--AxPSC--{0}--' -f $Name)}
        }
        if ($Secret){
            $null = Remove-AzKeyVaultSecret -VaultName $Info.VaultName -Name $Secret.Name -Force
        }
        return $?
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
        [hashtable] $AdditionalParameters
    )
    begin {
        # Set context
        $Info = Connect-AzVault -ContextName $AdditionalParameters.ContextName -VaultName $AdditionalParameters.VaultName
    }
    
    process {
        $pattern = [WildcardPattern]::new($Filter)
        $VaultSecrets = Get-AzKeyVaultSecret -VaultName $Info.VaultName
        foreach ($vs in $VaultSecrets) {
            if ($pattern.IsMatch($vs.Name)) {
                $Name = $vs.Name -replace '^--AxPSC--|--(.)+$'
                $Value = 'SecureString'
                if ($vs.Name -match '^--AxPSC--'){
                    $Value = 'PSCredential'
                }
                Write-Output ([pscustomobject] @{
                        Name  = $Name
                        Value = $Value 
                    })
            }
        }
    }
    
    end {
        if ($Info.Reset){
            $null = Set-AzContext $Info.InitialContext
        }
    }
}