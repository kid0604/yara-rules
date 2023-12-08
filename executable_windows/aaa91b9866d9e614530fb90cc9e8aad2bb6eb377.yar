import "pe"

rule Unspecified_Malware_Sep1_A1
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "28143c7638f22342bff8edcd0bedd708e265948a5fcca750c302e2dca95ed9f0"
		os = "windows"
		filetype = "executable"

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and pe.imphash()=="17a4bd9c95f2898add97f309fc6f9bcd")
}
