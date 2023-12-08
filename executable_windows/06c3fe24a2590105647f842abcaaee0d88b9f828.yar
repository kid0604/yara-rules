import "pe"

rule UPXModifiedstub
{
	meta:
		author = "malware-lu"
		description = "Detects a modified UPX stub in the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 [3] FF }

	condition:
		$a0 at pe.entry_point
}
