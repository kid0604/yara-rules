rule EquationGroup_cursezinger_linuxrh7_3_v_2_0_0
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "af7c7d03f59460fa60c48764201e18f3bd3f72441fd2e2ff6a562291134d2135"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = ",%02d%03d" fullword ascii
		$s2 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
		$s3 = "__strtoll_internal" fullword ascii
		$s4 = "__strtoul_internal" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <400KB and all of them )
}
