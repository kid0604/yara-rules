import "pe"

rule Pohernah101byKas
{
	meta:
		author = "malware-lu"
		description = "Detects the Pohernah101byKas malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 38 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 14 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

	condition:
		$a0 at pe.entry_point
}