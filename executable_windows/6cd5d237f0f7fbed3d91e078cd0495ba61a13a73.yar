rule CN_Honker_arp3_7_arp3_7
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file arp3.7.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "db641a9dfec103b98548ac7f6ca474715040f25c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "CnCerT.Net.SKiller.exe" fullword wide
		$s2 = "www.80sec.com" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and all of them
}
