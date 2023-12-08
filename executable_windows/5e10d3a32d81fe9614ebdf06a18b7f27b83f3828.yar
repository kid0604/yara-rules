import "pe"

rule eXPressorV13CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor v1.3 packed files from CGSoftLabs"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 }

	condition:
		$a0 at pe.entry_point
}
