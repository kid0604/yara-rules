rule Empire_PowerShell_Framework_Gen5
{
	meta:
		description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		super_rule = 1
		hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
		hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "if ($ExeArgs -ne $null -and $ExeArgs -ne '')" fullword ascii
		$s2 = "$ExeArgs = \"ReflectiveExe $ExeArgs\"" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <1000KB and 1 of them ) or all of them
}
