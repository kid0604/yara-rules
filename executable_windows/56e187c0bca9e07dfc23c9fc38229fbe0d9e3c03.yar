private rule PotaoUSB
{
	meta:
		description = "Detects the presence of PotaoUSB malware"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$binary1 = { 33 C0 8B C8 83 E1 03 BA ?? ?? ?? 00 2B D1 8A 0A 32 88 ?? ?? ?? 00 2A C8 FE C9 88 88 ?? ?? ?? 00 40 3D ?? ?? 00 00 7C DA C3 }
		$binary2 = { 55 8B EC 51 56 C7 45 FC 00 00 00 00 EB 09 8B 45 FC 83 C0 01 89 45 FC 81 7D FC ?? ?? 00 00 7D 3D 8B 4D FC 0F BE 89 ?? ?? ?? 00 8B 45 FC 33 D2 BE 04 00 00 00 F7 F6 B8 03 00 00 00 2B C2 0F BE 90 ?? ?? ?? 00 33 CA 2B 4D FC 83 E9 01 81 E1 FF 00 00 00 8B 45 FC 88 88 ?? ?? ?? 00 EB B1 5E 8B E5 5D C3}

	condition:
		($mz at 0) and any of ($binary*)
}
