import "pe"

rule PELockNTv201
{
	meta:
		author = "malware-lu"
		description = "Detects PELock NT v2.01"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }

	condition:
		$a0 at pe.entry_point
}
