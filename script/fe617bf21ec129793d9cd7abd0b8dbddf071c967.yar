rule EQGRP_screamingplow
{
	meta:
		description = "EQGRP Toolset Firewall - file screamingplow.sh"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "What is the name of your PBD:" fullword ascii
		$s2 = "You are now ready for a ScreamPlow" fullword ascii

	condition:
		1 of them
}
