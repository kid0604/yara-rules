import "pe"

rule APT_DarkHydrus_Jul18_2
{
	meta:
		description = "Detects strings found in malware samples in APT report in DarkHydrus"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
		date = "2018-07-28"
		hash1 = "b2571e3b4afbce56da8faa726b726eb465f2e5e5ed74cf3b172b5dd80460ad81"
		os = "windows"
		filetype = "executable"

	strings:
		$s4 = "windir" fullword ascii
		$s6 = "temp.dll" fullword ascii
		$s7 = "libgcj-12.dll" fullword ascii
		$s8 = "%s\\System32\\%s" fullword ascii
		$s9 = "StartW" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and all of them
}
