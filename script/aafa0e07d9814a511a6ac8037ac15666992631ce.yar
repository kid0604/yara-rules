rule lookupip
{
	meta:
		author = "x0r"
		description = "Lookup external IP"
		version = "0.1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$n1 = "checkip.dyndns.org" nocase
		$n2 = "whatismyip.org" nocase
		$n3 = "whatsmyipaddress.com" nocase
		$n4 = "getmyip.org" nocase
		$n5 = "getmyip.co.uk" nocase

	condition:
		any of them
}
