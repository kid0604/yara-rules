rule Domino_BackDoor
{
	meta:
		description = "Dectect Domino Backdoor"
		author = "@FarghlyMal"
		date = "2023/4/24"
		hash = "4ED1348A9A1A6917DBF77415C41CF7D19552394BCF76586E81516502C39D407C"
		os = "windows"
		filetype = "executable"

	strings:
		$S1 = {C7 44 24 ?? BB 01 00 00 [4-10] C7 44 24 ?? 50 00 00 00 [4-10]   
          C7 44 24 ?? 90 1F 00 00 [3-07] C7 44 24 ?? 35 00 00 00}
		$S2 = "ReflectiveLoader"

	condition:
		uint16(0)==0x5A4D and all of them
}
