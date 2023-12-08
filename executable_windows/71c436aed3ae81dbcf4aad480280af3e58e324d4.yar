rule Windows_Trojan_CobaltStrike_59b44767
{
	meta:
		author = "Elastic Security"
		id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
		fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies getsystem module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
		$b1 = "getsystem failed." ascii fullword
		$b2 = "_isSystemSID" ascii fullword
		$b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
		$c1 = "getsystem failed." ascii fullword
		$c2 = "$pdata$isSystemSID" ascii fullword
		$c3 = "$unwind$isSystemSID" ascii fullword
		$c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword

	condition:
		1 of ($a*) or 3 of ($b*) or 3 of ($c*)
}
