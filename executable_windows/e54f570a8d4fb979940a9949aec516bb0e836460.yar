import "pe"

rule SoftwareCompressV12BGSoftwareProtectTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects SoftwareCompressV12BGSoftwareProtectTechnologies malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 }

	condition:
		$a0 at pe.entry_point
}
