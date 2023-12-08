rule EQGRP_teflondoor
{
	meta:
		description = "Detects tool from EQGRP toolset - file teflondoor.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s: abort.  Code is %d.  Message is '%s'" fullword ascii
		$x2 = "%s: %li b (%li%%)" fullword ascii
		$s1 = "no winsock" fullword ascii
		$s2 = "%s: %s file '%s'" fullword ascii
		$s3 = "peer: connect" fullword ascii
		$s4 = "read: write" fullword ascii
		$s5 = "%s: done!" fullword ascii
		$s6 = "%s: %li b" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 1 of ($x*) and 3 of them
}
