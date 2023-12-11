import "pe"

rule ExeBundlev30standardloader
{
	meta:
		author = "malware-lu"
		description = "Detects a standard loader used in executable bundles"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB }

	condition:
		$a0 at pe.entry_point
}
