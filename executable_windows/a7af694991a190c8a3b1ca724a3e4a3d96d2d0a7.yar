import "pe"

rule VxGRUNT4Family
{
	meta:
		author = "malware-lu"
		description = "Detects VxGRUNT4 family of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 1C 00 8D 9E 41 01 40 3E 8B 96 14 03 B9 EA 00 87 DB F7 D0 31 17 83 C3 02 E2 F7 C3 }

	condition:
		$a0 at pe.entry_point
}
