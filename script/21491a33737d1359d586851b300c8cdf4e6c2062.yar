rule EQGRP_networkProfiler_orderScans
{
	meta:
		description = "EQGRP Toolset Firewall - file networkProfiler_orderScans.sh"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ea986ddee09352f342ac160e805312e3a901e58d2beddf79cd421443ba8c9898"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "Unable to save off predefinedScans directory" fullword ascii
		$x2 = "Re-orders the networkProfiler scans so they show up in order in the LP" fullword ascii

	condition:
		1 of them
}
