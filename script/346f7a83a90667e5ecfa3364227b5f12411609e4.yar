rule EQGRP_StoreFc
{
	meta:
		description = "EQGRP Toolset Firewall - file StoreFc.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "Usage: StoreFc.py --configFile=<path to xml file> --implantFile=<path to BinStore implant> [--outputFile=<file to write the conf" ascii
		$x2 = "raise Exception, \"Must supply both a config file and implant file.\"" fullword ascii
		$x3 = "This is wrapper for Store.py that FELONYCROWBAR will use. This" fullword ascii

	condition:
		1 of them
}
