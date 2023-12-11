rule PolishBankRAT_fdsvc_decode2
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Find a constant used as part of a payload decoding function in PolishBankRAT_fdsvc"
		os = "windows"
		filetype = "executable"

	strings:
		$part1 = {A6 EB 96}
		$part2 = {61 B2 E2 EF}
		$part3 = {0D CB E8 C4}
		$part4 = {5A F1 66 9C}
		$part5 = {A4 80 CD 9A}
		$part6 = {F1 2F 46 25}
		$part7 = {2F DB 16 26}
		$part8 = {4B C4 3F 3C}
		$str1 = "This program cannot be run in DOS mode"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
