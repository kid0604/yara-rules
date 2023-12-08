rule EQGRP_create_http_injection
{
	meta:
		description = "EQGRP Toolset Firewall - file create_http_injection.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "required by SECONDDATE" fullword ascii
		$s1 = "help='Output file name (optional). By default the resulting data is written to stdout.')" fullword ascii
		$s2 = "data = '<html><body onload=\"location.reload(true)\"><iframe src=\"%s\" height=\"1\" width=\"1\" scrolling=\"no\" frameborder=\"" ascii
		$s3 = "version='%prog 1.0'," fullword ascii
		$s4 = "usage='%prog [ ... options ... ] url'," fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <3KB and ($x1 or 2 of them )) or ( all of them )
}
