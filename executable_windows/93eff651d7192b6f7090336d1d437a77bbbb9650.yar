import "pe"

rule ProActivateV10XTurboPowerSoftwareCompany
{
	meta:
		author = "malware-lu"
		description = "Detects ProActivateV10XTurboPowerSoftwareCompany malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 [4] 90 90 90 90 90 33 C0 55 68 [4] 64 FF 30 64 89 20 A1 [4] 83 C0 05 A3 [4] C7 05 [4] 0D 00 00 00 E8 85 E2 FF FF 81 3D [4] 21 7E 7E 40 75 7A 81 3D [4] 43 52 43 33 75 6E 81 3D [4] 32 40 7E 7E 75 62 81 3D [4] 21 7E 7E 40 75 56 81 3D [4] 43 52 43 33 75 4A 81 3D [4] 32 40 7E 7E 75 3E 81 3D [4] 21 7E 7E 40 75 32 81 3D [4] 43 52 43 33 }

	condition:
		$a0 at pe.entry_point
}
