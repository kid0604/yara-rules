rule EquationGroup_watcher_linux_x86_64_v_3_3_0
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "a8d65593f6296d6d06230bcede53b9152842f1eee56a2a72b0a88c4f463a09c3"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "forceprismheader" fullword ascii
		$s2 = "invalid option `" fullword ascii
		$s3 = "forceprism" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <900KB and all of them )
}
