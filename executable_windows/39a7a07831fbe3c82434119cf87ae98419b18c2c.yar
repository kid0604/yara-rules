import "pe"

rule PEBundlev244
{
	meta:
		author = "malware-lu"
		description = "Detects a specific PE file with a certain byte pattern at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB [2] 40 ?? 87 DD 83 BD }

	condition:
		$a0 at pe.entry_point
}
