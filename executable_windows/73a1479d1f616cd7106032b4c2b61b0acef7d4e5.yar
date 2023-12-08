import "pe"

rule MALWARE_Win_Gelsevirine
{
	meta:
		author = "ditekSHen"
		description = "Detects Gelsevirine"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = /64loadpath(xp|sv|7)/ fullword wide
		$s2 = "{\"Actions\":[]}" fullword wide
		$s3 = "PlatformsChunk" fullword wide
		$s4 = "CurrentPluginCategory" fullword wide
		$s5 = "CurrentOperationPlatform" fullword wide
		$s6 = "PersistencePlugins" fullword wide
		$s7 = "memory_library_file" fullword wide
		$s8 = "LoadPluginBP" fullword ascii
		$s9 = "GetOperationBasicInformation" fullword ascii
		$s10 = "commonappdata/Intel/Runtime" wide
		$s11 = "cfsst x64" fullword wide
		$s12 = "ForkOperation" fullword ascii
		$c1 = "domain.dns04.com:8080;domain.dns04.com:443;acro.ns1.name:80;acro.ns1.name:1863;" wide
		$c2 = "<base64 content=\"" fullword ascii
		$c3 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
		$m1 = "6BDA7FEF-232F-4EA6-8FC8-24F58CD7B366" ascii wide
		$m2 = "46EBBDC3-EEDC-42D4-BA1D-D454DFCE8E42" ascii wide
		$m3 = "135054C6-8036-42C7-A97C-31F37D7728BD" ascii wide
		$m4 = "DC7FDDF7-B2F1-4B99-BE6A-AA683FF11CE6" ascii wide
		$m5 = "131C8113-E083-4C7F-BEAF-82D73B01F2C5" ascii wide
		$m6 = "4CCF506D-2F61-4C3A-B9C6-9FA47D43A3FC" ascii wide
		$m7 = "B2DC745A-66AE-4A19-B11C-AD74D46B7EE0" ascii wide
		$m8 = "6BDA7FEF-232F-4EA6-8FC8-24F58CD7B366" ascii wide

	condition:
		uint16(0)==0x5a4d and (6 of ($s*) or (2 of ($c*) and 4 of ($s*)) or (5 of ($m*) and (1 of ($c*) or 3 of ($s*))))
}
