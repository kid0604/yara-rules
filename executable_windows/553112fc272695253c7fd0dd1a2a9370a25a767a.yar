import "pe"

rule PEBundlev20b5v23
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate the presence of a certain type of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB [2] 40 ?? 87 DD 01 AD [4] 01 AD }

	condition:
		$a0 at pe.entry_point
}
