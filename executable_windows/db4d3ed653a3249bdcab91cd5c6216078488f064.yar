import "pe"

rule Shrinkerv32
{
	meta:
		author = "malware-lu"
		description = "Detects Shrinker v3.2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D [5] 55 8B EC 56 57 75 65 68 00 01 [2] E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 [4] 85 F6 74 1D 68 FF }

	condition:
		$a0 at pe.entry_point
}
