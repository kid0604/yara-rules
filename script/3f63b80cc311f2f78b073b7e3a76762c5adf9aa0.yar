rule EQGRP_create_dns_injection
{
	meta:
		description = "EQGRP Toolset Firewall - file create_dns_injection.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "488f3cc21db0688d09e13eb85a197a1d37902612c3e302132c84e07bc42b1c32"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "Name:   A hostname: 'host.network.com', a decimal numeric offset within" fullword ascii
		$s2 = "-a www.badguy.net,CNAME,1800,host.badguy.net \\\\" fullword ascii

	condition:
		1 of them
}
