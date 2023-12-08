import "pe"

rule VXTibsZhelatinStormWormvariant
{
	meta:
		author = "malware-lu"
		description = "Detects VXTibs/Zhelatin/Storm Worm variant"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FF 74 24 1C 58 8D 80 [2] 77 04 50 68 62 34 35 04 E8 }

	condition:
		$a0 at pe.entry_point
}
