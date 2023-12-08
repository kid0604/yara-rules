import "pe"

rule DAEMONProtectv067
{
	meta:
		author = "malware-lu"
		description = "Detects DAEMONProtectv067 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }

	condition:
		$a0 at pe.entry_point
}
