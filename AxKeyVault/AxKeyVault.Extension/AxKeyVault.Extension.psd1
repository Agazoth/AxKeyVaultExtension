@{ 
    ModuleVersion = '1.0';
    RootModule = '.\AxKeyVault.Extension.psm1';
    FunctionsToExport = @('Set-Secret', 'Get-Secret', 'Remove-Secret', 'Get-SecretInfo', 'Test-SecretVault')
}
