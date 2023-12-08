import "pe"

rule VProtectorV11Avcasm
{
	meta:
		author = "malware-lu"
		description = "Detects VProtector V11 AVCasm malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
