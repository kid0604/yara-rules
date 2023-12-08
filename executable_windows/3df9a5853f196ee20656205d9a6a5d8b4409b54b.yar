import "pe"

rule XPack167
{
	meta:
		author = "malware-lu"
		description = "Detects XPack167 malware based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }

	condition:
		$a0 at pe.entry_point
}
