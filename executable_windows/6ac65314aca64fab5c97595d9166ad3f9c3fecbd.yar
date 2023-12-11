rule Spora
{
	meta:
		author = "pekeinfo"
		date = "2017-02-22"
		description = "Spora"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {7B 7F 4E 11 5D F3 FE 15 F9 55 FD 00 AD E9 CF FE E2 56 78 03 D0 21 46 00 30 68 C4 D0 01 FD 00 C3 B7 00 4A 0D 57 D2 52 91 05}
		$b = {6F 51 3E 6B F9 15 29 D9 DF 26 1E 80 62 8A 0D E3 64 51 3B 0F F3 FE FF FF F3 FE FF FF F3 FE FF FF F3 FE FF FF}

	condition:
		$a and $b
}
