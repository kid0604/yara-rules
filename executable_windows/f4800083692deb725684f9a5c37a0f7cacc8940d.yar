import "pe"

rule MinkeV101Codius
{
	meta:
		author = "malware-lu"
		description = "Detects MinkeV101Codius malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 26 3D 4F 38 C2 82 37 B8 F3 24 42 03 17 9B 3A 83 01 00 00 CC 00 00 00 00 06 00 00 00 01 64 53 74 75 62 00 10 55 54 79 70 65 73 00 00 C7 53 79 73 74 65 6D 00 00 81 53 79 73 49 6E 69 74 00 0C 4B 57 69 6E 64 6F 77 73 00 00 8A 75 46 75 6E 63 74 69 6F 6E 73 }

	condition:
		$a0
}
