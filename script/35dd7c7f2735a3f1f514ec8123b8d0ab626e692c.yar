rule EQGRP_userscript
{
	meta:
		description = "EQGRP Toolset Firewall - file userscript.FW"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii

	condition:
		1 of them
}
