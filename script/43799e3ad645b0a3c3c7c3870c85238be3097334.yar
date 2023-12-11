rule EQGRP_tinyhttp_setup
{
	meta:
		description = "EQGRP Toolset Firewall - file tinyhttp_setup.sh"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "3d12c83067a9f40f2f5558d3cf3434bbc9a4c3bb9d66d0e3c0b09b9841c766a0"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "firefox http://127.0.0.1:8000/$_name" fullword ascii
		$x2 = "What is the name of your implant:" fullword ascii
		$x3 = "killall thttpd" fullword ascii
		$x4 = "copy http://<IP>:80/$_name flash:/$_name" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <2KB and 1 of ($x*)) or ( all of them )
}
