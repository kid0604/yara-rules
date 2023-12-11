import "pe"

rule Armadillov1xxv2xx
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v1.xx and v2.xx packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }

	condition:
		$a0 at pe.entry_point
}
