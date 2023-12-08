import "pe"

rule PEStubOEPv1x
{
	meta:
		author = "malware-lu"
		description = "Detects PE files with a specific OEP stub"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 40 48 BE 00 [2] 00 40 48 60 33 C0 B8 [3] 00 FF E0 C3 C3 }

	condition:
		$a0
}
