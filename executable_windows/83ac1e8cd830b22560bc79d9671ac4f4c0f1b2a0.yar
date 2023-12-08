import "pe"

rule Kryptonv03
{
	meta:
		author = "malware-lu"
		description = "Detects Kryptonv03 malware based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }

	condition:
		$a0 at pe.entry_point
}
