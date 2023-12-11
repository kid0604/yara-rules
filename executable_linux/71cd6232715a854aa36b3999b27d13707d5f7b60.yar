rule EquationGroup_pclean_v2_1_1_2
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file pclean.v2.1.1.0-linux-i386"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
		os = "linux"
		filetype = "executable"

	strings:
		$s3 = "** SIGNIFICANTLY IMPROVE PROCESSING TIME" fullword ascii
		$s6 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and all of them )
}
