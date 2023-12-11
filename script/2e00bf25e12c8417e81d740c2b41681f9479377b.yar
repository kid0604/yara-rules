rule lookupgeo
{
	meta:
		author = "x0r"
		description = "Lookup Geolocation"
		version = "0.1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$n1 = "j.maxmind.com" nocase

	condition:
		any of them
}
