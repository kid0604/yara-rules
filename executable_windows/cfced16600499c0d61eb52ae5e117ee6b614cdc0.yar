rule GRIZZLY_STEPPE_Malware_1
{
	meta:
		description = "Auto-generated rule - file HRDG022184_certclint.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/WVflzO"
		date = "2016-12-29"
		hash1 = "9f918fb741e951a10e68ce6874b839aef5a26d60486db31e509f8dcaa13acec5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb" fullword ascii
		$s2 = "Repeat last find command)Replace specific text with different text" fullword wide
		$s3 = "l\\Processor(0)\\% Processor Time" fullword wide
		$s6 = "Self Process" fullword wide
		$s7 = "Default Process" fullword wide
		$s8 = "Star Polk.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 4 of them )
}
