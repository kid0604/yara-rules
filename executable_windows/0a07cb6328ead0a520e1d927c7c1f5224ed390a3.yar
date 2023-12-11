import "pe"

rule Splice11byTw1stedL0gic
{
	meta:
		author = "malware-lu"
		description = "Detects the Splice11byTw1stedL0gic malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 [16] 00 00 00 00 00 00 01 00 00 00 [6] 50 72 6F 6A 65 63 74 31 00 [7] 00 00 00 00 06 00 00 00 AC 29 40 00 07 00 00 00 BC 28 40 00 07 00 00 00 74 28 40 00 07 00 00 00 2C 28 40 00 07 00 00 00 08 23 40 00 01 00 00 00 38 21 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 8C 21 40 00 08 ?? 40 00 01 00 00 00 AC 19 40 00 00 00 00 00 00 00 00 00 00 00 00 00 AC 19 40 00 4F 00 43 00 50 00 00 00 E7 AF 58 2F 9A 4C 17 4D B7 A9 CA 3E 57 6F F7 76 }

	condition:
		$a0 at pe.entry_point
}
