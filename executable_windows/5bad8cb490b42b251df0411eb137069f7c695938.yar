rule EquationGroup_Toolset_Apr17__Emphasismine
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "dcaf91bd4af7cc7d1fb24b5292be4e99c7adf4147892f6b3b909d1d84dd4e45b"
		hash2 = "348eb0a6592fcf9da816f4f7fc134bcae1b61c880d7574f4e19398c4ea467f26"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Error: Could not calloc() for shellcode buffer" fullword ascii
		$x2 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii
		$x3 = "Generating shellcode" fullword ascii
		$x4 = "([0-9a-zA-Z]+) OK LOGOUT completed" fullword ascii
		$x5 = "Error: Domino is not the expected version. (%s, %s)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
