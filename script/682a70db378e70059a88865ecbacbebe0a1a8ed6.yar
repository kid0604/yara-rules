rule EQGRP_sploit_py
{
	meta:
		description = "EQGRP Toolset Firewall - file sploit.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
		$x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
		$x3 = "[-] no response from health check - target may have crashed" fullword ascii

	condition:
		1 of them
}
