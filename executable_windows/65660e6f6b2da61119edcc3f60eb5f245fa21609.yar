import "pe"

rule DingBoysPElockPhantasmv15b3
{
	meta:
		author = "malware-lu"
		description = "Detects the DingBoysPElockPhantasmv15b3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

	condition:
		$a0 at pe.entry_point
}
