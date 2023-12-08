rule Sality_Malware_Oct16
{
	meta:
		description = "Detects an unspecififed malware - October 2016"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-10-08"
		score = 80
		hash1 = "8eaff5e1d4b55dd6e25f007549271da10afd1fa25064d7105de0ca2735487aad"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Hello world!" fullword wide
		$s2 = "[LordPE]" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
