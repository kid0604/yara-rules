import "pe"

rule AnticrackSoftwareProtectorv109ACProtect
{
	meta:
		author = "malware-lu"
		description = "Detects Anticrack Software Protector v1.09 (ACProtect) usage"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 [8] 00 00 [12] E8 01 00 00 00 ?? 83 04 24 06 C3 [5] 00 }

	condition:
		$a0 at pe.entry_point
}
