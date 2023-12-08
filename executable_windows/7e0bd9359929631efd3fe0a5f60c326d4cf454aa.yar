rule Windows_Trojan_CobaltStrike_92f05172
{
	meta:
		author = "Elastic Security"
		id = "92f05172-f15c-4077-a958-b8490378bf08"
		fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC cmstp module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
		$b1 = "elevate_cmstp" ascii fullword
		$b2 = "$pdata$elevate_cmstp" ascii fullword
		$b3 = "$unwind$elevate_cmstp" ascii fullword
		$c1 = "_elevate_cmstp" ascii fullword
		$c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
		$c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
		$c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
		$c5 = "OLDNAMES"
		$c6 = "__imp__BeaconDataParse" ascii fullword
		$c7 = "_willAutoElevate" ascii fullword

	condition:
		1 of ($a*) or 3 of ($b*) or 4 of ($c*)
}
