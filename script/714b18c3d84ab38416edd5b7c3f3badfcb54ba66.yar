rule EQGRP_config_jp1_UA
{
	meta:
		description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "This program will configure a JETPLOW Userarea file." fullword ascii
		$x2 = "Error running config_implant." fullword ascii
		$x3 = "NOTE:  IT ASSUMES YOU ARE OPERATING IN THE INSTALL/LP/JP DIRECTORY. THIS ASSUMPTION " fullword ascii
		$x4 = "First IP address for beacon destination [127.0.0.1]" fullword ascii

	condition:
		1 of them
}
