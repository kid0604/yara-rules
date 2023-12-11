import "pe"

rule Shrinkerv33
{
	meta:
		author = "malware-lu"
		description = "Detects Shrinker v3.3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D [3] 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

	condition:
		$a0 at pe.entry_point
}
