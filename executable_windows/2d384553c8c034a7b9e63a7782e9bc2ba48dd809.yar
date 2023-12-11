import "pe"

rule RPolyCryptv10personalpolycryptorsignfrompinch
{
	meta:
		author = "malware-lu"
		description = "Detects the RPolyCryptv10 personal poly cryptor sign from Pinch malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 58 97 97 60 61 8B 04 24 80 78 F3 6A E8 00 00 00 00 58 E8 00 00 00 00 58 91 91 EB 00 0F 85 6B F4 76 6F E8 00 00 00 00 83 C4 04 E8 00 00 00 00 58 90 E8 00 00 00 00 83 C4 04 8B 04 24 80 78 F1 }

	condition:
		$a0 at pe.entry_point
}
