rule EquationGroup_Toolset_Apr17_Gen1
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "1b5b33931eb29733a42d18d8ee85b5cd7d53e81892ff3e60e2e97f3d0b184d31"
		hash2 = "139697168e4f0a2cc73105205c0ddc90c357df38d93dbade761392184df680c7"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Restart with the new protocol, address, and port as target." fullword ascii
		$x2 = "TargetPort      : %s (%u)" fullword ascii
		$x3 = "Error: strchr() could not find '@' in account name." fullword ascii
		$x4 = "TargetAcctPwd   : %s" fullword ascii
		$x5 = "Creating CURL connection handle..." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and 1 of them )
}
