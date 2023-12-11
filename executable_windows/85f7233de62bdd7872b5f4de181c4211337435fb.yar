import "pe"

rule PELockNTv203
{
	meta:
		author = "malware-lu"
		description = "Detects PELock NT v2.03"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}
