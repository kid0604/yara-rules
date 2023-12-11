rule EquationGroup__pclean_v2_1_1_pclean_v2_1_1_4
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files pclean.v2.1.1.0-linux-i386, pclean.v2.1.1.0-linux-x86_64"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		super_rule = 1
		hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
		hash2 = "ab7f26faed8bc2341d0517d9cb2bbf41795f753cd21340887fc2803dc1b9a1dd"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
		$s2 = "e.g.: -n 1-1024,1080,6666,31337 " fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <50KB and all of them )
}
