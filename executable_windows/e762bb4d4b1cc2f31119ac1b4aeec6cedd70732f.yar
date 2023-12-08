import "pe"

rule PESpinV11cyberbob
{
	meta:
		author = "malware-lu"
		description = "Detects PESpin v1.1 cyberbob malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }

	condition:
		$a0 at pe.entry_point
}
