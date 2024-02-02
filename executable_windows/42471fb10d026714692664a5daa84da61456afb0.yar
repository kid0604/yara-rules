rule mal_asuka_stealer
{
	meta:
		author = "RussianPanda"
		description = "Detects AsukaStealer"
		date = "2/2/2024"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {32 14 3E E8 F6 81 00 00}
		$s2 = {00 58 00 2D 00 43 00 6F 00 6E 00 66 00 69 00 67}
		$s3 = {58 00 2D 00 49 00 6E 00 66 00 6F}

	condition:
		uint16(0)==0x5A4D and all of them
}
