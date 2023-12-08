import "pe"

rule eXPressorv13CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor v1.3 CGSoftLabs packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 33 2E }
		$a1 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 [4] 2B 05 [4] A3 [4] 83 3D [4] 00 74 13 A1 [4] 03 05 [4] 89 [2] E9 [2] 00 00 C7 05 }

	condition:
		$a0 or $a1 at pe.entry_point
}
