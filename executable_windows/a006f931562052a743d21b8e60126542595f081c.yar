rule unk_packer
{
	meta:
		author = "pekeinfo"
		date = "2017-02-22"
		description = "Spora & Cerber ek"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {0E 9E 52 69 C8 E4 73 BF 87 2B 95 15 33 1B B7 6B 46 62 D8 C1 01 A9 F9 17 FC EF 1A 6E B7 36 3C C4 72 7D 5D 1A 2D C4 7E 70 E8 0A A0 C6 A3 51 C1 1C 5E 98 E2 72 19 DF 03 C9 D4 25 25 1F EF 6B 46 75 9C BB 1D D2 57 56 35 75 31 35 56 8F B7 5B 23 3D }
		$b = {00 10 00 2E E8 77 EC FF FF 85 C0 0F 85 78 C4 FF}

	condition:
		$a and $b
}
