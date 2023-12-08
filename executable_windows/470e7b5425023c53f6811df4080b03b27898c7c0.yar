rule EQGRP_BBALL_M50FW08_2201
{
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "pageTable.c" fullword ascii
		$s4 = "_start_text" fullword ascii
		$s5 = "handler_readBIOS" fullword ascii
		$s6 = "KEEPGOING" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and 5 of ($s*))
}
