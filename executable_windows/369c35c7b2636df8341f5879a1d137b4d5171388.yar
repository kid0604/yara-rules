import "pe"

rule ExeBundlev30smallloader
{
	meta:
		author = "malware-lu"
		description = "Detects a small loader used in executable bundles"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 }

	condition:
		$a0 at pe.entry_point
}
