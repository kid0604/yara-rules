rule KR_Target_Malware_Aug17
{
	meta:
		description = "Detects malware that targeted South Korea in Aug 2017 - file MRDqsbuEqGxrgqtbXU.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/eyalsela/status/900250203097354240"
		date = "2017-08-23"
		hash1 = "82cada01643a42c8cd9600b8c33f3760d15e5eb6fabec2d531cf13cece095c78"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = { 53 00 75 00 63 00 63 00 65 00 00 2F 53 00 6F 00
               6D 00 65 00 74 00 68 00 69 00 6E 00 67 00 20 00
               77 00 65 00 6E 00 74 00 20 00 77 00 72 00 6F 00
               6E 00 67 00 }
		$x2 = "lnVMODvjSfOQQnfiuFogghlL" fullword ascii
		$x3 = "E X I T  +R U N A S  /a P P d A T A " fullword ascii
		$x4 = "uSEsHELLeXECUTE gETeNTRYaSSEMBLY GET" fullword ascii
		$x5 = "ZahUKBXz" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and 1 of them )
}
