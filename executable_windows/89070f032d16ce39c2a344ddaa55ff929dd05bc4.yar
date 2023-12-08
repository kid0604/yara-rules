rule Windows_Trojan_CobaltStrike_8a791eb7
{
	meta:
		author = "Elastic Security"
		id = "8a791eb7-dc0c-4150-9e5b-2dc21af0c77d"
		fingerprint = "4967886ba5e663f2e2dc0631939308d7d8f2194a30590a230973e1b91bd625e1"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Registry module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
		$b1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
		$b2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
		$b3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
		$b4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
		$b5 = "__imp_BeaconFormatAlloc" ascii fullword
		$b6 = "__imp_BeaconOutput" ascii fullword
		$b7 = "__imp_BeaconFormatFree" ascii fullword
		$b8 = "__imp_BeaconDataPtr" ascii fullword
		$c1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
		$c2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
		$c3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
		$c4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
		$c5 = "__imp__BeaconFormatAlloc" ascii fullword
		$c6 = "__imp__BeaconOutput" ascii fullword
		$c7 = "__imp__BeaconFormatFree" ascii fullword
		$c8 = "__imp__BeaconDataPtr" ascii fullword

	condition:
		1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}
