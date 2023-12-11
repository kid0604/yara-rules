import "pe"

rule ExeShieldvxx
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ExeShield version XX"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }

	condition:
		$a0 at pe.entry_point
}
