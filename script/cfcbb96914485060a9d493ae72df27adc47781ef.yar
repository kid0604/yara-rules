rule EQGRP_payload
{
	meta:
		description = "EQGRP Toolset Firewall - file payload.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "can't find target version module!" fullword ascii
		$s2 = "class Payload:" fullword ascii

	condition:
		all of them
}
