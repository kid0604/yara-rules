rule EquationGroup_Toolset_Apr17_Architouch_1_0_0
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[+] Target is %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
