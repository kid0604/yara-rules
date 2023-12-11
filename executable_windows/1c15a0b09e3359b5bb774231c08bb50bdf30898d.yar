import "pe"

rule PECrypt15BitShapeSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects 15-bit SHAPE Software encrypted PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 55 20 40 00 B9 7B 09 00 00 8D BD 9D 20 40 00 8B F7 AC [48] AA E2 CC }

	condition:
		$a0 at pe.entry_point
}
