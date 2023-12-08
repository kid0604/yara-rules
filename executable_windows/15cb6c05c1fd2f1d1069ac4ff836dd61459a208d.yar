import "pe"

rule UPackAltStubDwing
{
	meta:
		author = "malware-lu"
		description = "Detects UPackAltStubDwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 09 00 00 00 C3 F6 00 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD }

	condition:
		$a0 at pe.entry_point
}
