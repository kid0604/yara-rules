rule Windows_Trojan_CobaltStrike_15f680fb
{
	meta:
		author = "Elastic Security"
		id = "15f680fb-a04f-472d-a182-0b9bee111351"
		fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Netview module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "netview.x64.dll" ascii fullword
		$a2 = "netview.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\netview" ascii fullword
		$b1 = "Sessions for \\\\%s:" ascii fullword
		$b2 = "Account information for %s on \\\\%s:" ascii fullword
		$b3 = "Users for \\\\%s:" ascii fullword
		$b4 = "Shares at \\\\%s:" ascii fullword
		$b5 = "ReflectiveLoader" ascii fullword
		$b6 = "Password changeable" ascii fullword
		$b7 = "User's Comment" wide fullword
		$b8 = "List of hosts for domain '%s':" ascii fullword
		$b9 = "Password changeable" ascii fullword
		$b10 = "Logged on users at \\\\%s:" ascii fullword

	condition:
		2 of ($a*) or 6 of ($b*)
}
