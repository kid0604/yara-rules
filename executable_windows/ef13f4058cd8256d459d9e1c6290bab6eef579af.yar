rule EquationGroup_Toolset_Apr17__ETBL_ETRE_SMBTOUCH_17
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
		hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
		hash3 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "ERROR: Connection terminated by Target (TCP Ack/Fin)" fullword ascii
		$s2 = "Target did not respond within specified amount of time" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
