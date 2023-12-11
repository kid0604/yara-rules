import "pe"

rule FSGv11_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects a specific byte sequence at the entry point of a PE file, which may indicate the presence of a certain type of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE [4] FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }

	condition:
		$a0 at pe.entry_point
}
