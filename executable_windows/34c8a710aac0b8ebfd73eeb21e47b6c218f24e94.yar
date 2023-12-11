import "pe"

rule WiltedTulip_Netsrv_netsrvs
{
	meta:
		description = "Detects sample from Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "a062cb4364125427b54375d51e9e9afb0baeb09b05a600937f70c9d6d365f4e5"
		hash2 = "afa563221aac89f96c383f9f9f4ef81d82c69419f124a80b7f4a8c437d83ce77"
		hash3 = "acf24620e544f79e55fd8ae6022e040257b60b33cf474c37f2877c39fbf2308a"
		hash4 = "bff115d5fb4fd8a395d158fb18175d1d183c8869d54624c706ee48a1180b2361"
		hash5 = "07ab795eeb16421a50c36257e6e703188a0fef9ed87647e588d0cd2fcf56fe43"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Process %d Created" fullword ascii
		$s2 = "%s\\system32\\rundll32.exe" fullword wide
		$s3 = "%s\\SysWOW64\\rundll32.exe" fullword wide
		$c1 = "slbhttps" fullword ascii
		$c2 = "/slbhttps" fullword wide
		$c3 = "/slbdnsk1" fullword wide
		$c4 = "netsrv" fullword wide
		$c5 = "/slbhttps" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and ( all of ($s*) and 1 of ($c*)))
}
