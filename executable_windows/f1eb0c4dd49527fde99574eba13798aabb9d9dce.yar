import "pe"

rule PEProtector093CRYPToCRACk
{
	meta:
		author = "malware-lu"
		description = "Detects a specific PE protector used to crack encryption"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00 }

	condition:
		$a0 at pe.entry_point
}
