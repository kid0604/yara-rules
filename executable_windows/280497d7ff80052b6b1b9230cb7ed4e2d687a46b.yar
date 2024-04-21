rule LummaRemap
{
	meta:
		author = "kevoreilly"
		description = "Lumma ntdll-remap bypass"
		cape_options = "ntdll-remap=0"
		packed = "7972cbf2c143cea3f90f4d8a9ed3d39ac13980adfdcf8ff766b574e2bbcef1b4"
		os = "windows"
		filetype = "executable"

	strings:
		$remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}

	condition:
		uint16(0)==0x5a4d and any of them
}
