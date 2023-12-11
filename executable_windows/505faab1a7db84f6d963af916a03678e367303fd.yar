rule EquationGroup_Toolset_Apr17_Architouch_Eternalsynergy_Smbtouch
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
		hash2 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
		hash3 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "NtErrorMoreProcessingRequired" fullword ascii
		$s2 = "Command Format Error: Error=%x" fullword ascii
		$s3 = "NtErrorPasswordRestriction" fullword ascii
		$op0 = { 8a 85 58 ff ff ff 88 43 4d }

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 2 of them )
}
