rule Empire_PowerShell_Framework_Gen4
{
	meta:
		description = "Detects Empire component - from files Invoke-BypassUAC.ps1, Invoke-CredentialInjection.ps1, Invoke-CredentialInjection.ps1, Invoke-DCSync.ps1, Invoke-DllInjection.ps1, Invoke-Mimikatz.ps1, Invoke-PsExec.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1, Invoke-Shellcode.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		super_rule = 1
		hash1 = "743c51334f17751cfd881be84b56f648edbdaf31f8186de88d094892edc644a9"
		hash2 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash3 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash4 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
		hash5 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
		hash6 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
		hash7 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
		hash8 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
		hash9 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
		hash10 = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }" fullword ascii
		$s2 = "# Get a handle to the module specified" fullword ascii
		$s3 = "$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))" fullword ascii
		$s4 = "$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
