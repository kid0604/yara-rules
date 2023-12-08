rule EquationGroup_Toolset_Apr17_lp_mstcp
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "2ab1e1d23021d887759750a0c053522e9149b7445f840936bbc7e703f8700abd"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s2 = "_PacketNDISRequestComplete@12\"" fullword ascii
		$s3 = "_LDNdis5RegDeleteKeys@4" fullword ascii
		$op1 = { 89 7e 04 75 06 66 21 46 02 eb }
		$op2 = { fc 74 1b 8b 49 04 0f b7 d3 66 83 }
		$op3 = { aa 0f b7 45 fc 8b 52 04 8d 4e }

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and ( all of ($s*) or all of ($op*)))
}
