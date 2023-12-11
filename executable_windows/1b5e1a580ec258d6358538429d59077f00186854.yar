import "pe"

rule JDPackV200JDPack
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting JDPackV200JDPack malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 [3] E8 01 00 00 00 [6] 05 00 00 00 00 83 C4 0C 5D 60 E8 00 00 00 00 5D 8B D5 64 FF 35 00 00 00 00 EB }

	condition:
		$a0 at pe.entry_point
}
