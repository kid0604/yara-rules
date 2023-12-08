import "pe"

rule PELockv106
{
	meta:
		author = "malware-lu"
		description = "Detects PELock v1.06 protected files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }

	condition:
		$a0 at pe.entry_point
}
