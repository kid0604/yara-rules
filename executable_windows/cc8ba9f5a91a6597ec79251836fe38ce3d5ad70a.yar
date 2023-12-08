import "pe"

rule PELockNTv202c
{
	meta:
		author = "malware-lu"
		description = "Detects PELockNTv202c malware by checking for specific entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }

	condition:
		$a0 at pe.entry_point
}
