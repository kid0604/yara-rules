import "pe"

rule VidgrabCode : Vidgrab Family
{
	meta:
		description = "Vidgrab code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-20"
		os = "windows"
		filetype = "executable"

	strings:
		$divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
		$xorloop = { 03 C1 80 30 (66 | 58) 41 }
		$junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }

	condition:
		all of them
}
