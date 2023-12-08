import "pe"

rule PENinjamodified
{
	meta:
		author = "malware-lu"
		description = "Detects a modified version of the PENinja malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }

	condition:
		$a0 at pe.entry_point
}
