import "pe"

rule FSGv133_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects a specific byte sequence at the entry point of a PE file, which may indicate the presence of a certain type of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }

	condition:
		$a0 at pe.entry_point
}
