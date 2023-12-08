rule EquationGroup_Toolset_Apr17_svctouch
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "96b6a3c4f53f9e7047aa99fd949154745e05dc2fd2eb21ef6f0f9b95234d516b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <10KB and 1 of them )
}
