import "pe"

rule TPPpackclane
{
	meta:
		author = "malware-lu"
		description = "Detects TPPpackclane malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8 }

	condition:
		$a0 at pe.entry_point
}
