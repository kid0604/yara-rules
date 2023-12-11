import "pe"

rule RatPackerGluestub
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RatPacker Gluestub in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }

	condition:
		$a0 at pe.entry_point
}
