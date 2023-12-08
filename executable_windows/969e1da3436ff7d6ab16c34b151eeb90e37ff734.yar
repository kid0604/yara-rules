rule Sofacy_Jun16_Sample1
{
	meta:
		description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/mzAa97"
		date = "2016-06-14"
		score = 85
		hash1 = "be1cfa10fcf2668ae01b98579b345ebe87dab77b6b1581c368d1aba9fd2f10a0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "clconfg.dll" fullword ascii
		$s2 = "ASijnoKGszdpodPPiaoaghj8127391" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($s*))) or ( all of them )
}
