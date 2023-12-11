import "pe"

rule Enfal_Malware_Backdoor
{
	meta:
		description = "Generic Rule to detect the Enfal Malware"
		author = "Florian Roth"
		date = "2015/02/10"
		super_rule = 1
		hash0 = "6d484daba3927fc0744b1bbd7981a56ebef95790"
		hash1 = "d4071272cc1bf944e3867db299b3f5dce126f82b"
		hash2 = "6c7c8b804cc76e2c208c6e3b6453cb134d01fa41"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$x1 = "Micorsoft Corportation" fullword wide
		$x2 = "IM Monnitor Service" fullword wide
		$s1 = "imemonsvc.dll" fullword wide
		$s2 = "iphlpsvc.tmp" fullword
		$z1 = "urlmon" fullword
		$z2 = "Registered trademarks and service marks are the property of their respec" wide
		$z3 = "XpsUnregisterServer" fullword
		$z4 = "XpsRegisterServer" fullword
		$z5 = "{53A4988C-F91F-4054-9076-220AC5EC03F3}" fullword

	condition:
		($mz at 0) and (1 of ($x*) or ( all of ($s*) and all of ($z*)))
}
