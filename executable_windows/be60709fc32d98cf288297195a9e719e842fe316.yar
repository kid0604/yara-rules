import "pe"

rule Greenbug_Malware_5
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		modified = "2023-01-27"
		super_rule = 1
		hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
		hash2 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
		hash3 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
		hash4 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd /u /c WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter" fullword ascii
		$x2 = "cmd /a /c net user administrator /domain >>" fullword ascii
		$x3 = "cmd /a /c netstat -ant >>\"%localappdata%\\Microsoft\\" ascii
		$o1 = "========================== (Net User) ==========================" ascii fullword

	condition:
		filesize <2000KB and (( uint16(0)==0x5a4d and 1 of them ) or $o1)
}
