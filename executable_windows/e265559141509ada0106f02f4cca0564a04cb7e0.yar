import "pe"

rule VxGRUNT2Family
{
	meta:
		author = "malware-lu"
		description = "Detects VxGRUNT2 family of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3 }

	condition:
		$a0 at pe.entry_point
}
