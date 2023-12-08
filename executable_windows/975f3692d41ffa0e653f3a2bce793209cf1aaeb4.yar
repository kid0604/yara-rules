import "hash"
import "pe"

rule Ransom_Sodinokibi
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "2!2&2>2K2R2Z2_2d2i2"
		$s2 = "ERR0R D0UBLE RUN!"
		$s3 = "4!5&575?5R5Z5~5"
		$s4 = "344<4E4Z4f4p4x4"
		$s5 = "?%?+?1?7?=?K?_?"
		$s6 = "DTrump4ever"
		$s7 = "3N,3NT3N|3"
		$s8 = {65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65}
		$s9 = {76 00 6D 00 63 00 6F 00 6D 00 70 00 75 00 74 00 65 00 2E 00 65 00 78 00 65}
		$s10 = {76 00 6D 00 6D 00 73 00 2E 00 65 00 78 00 65 00 00 00 00 00 76 00 6D 00 77 00 70 00 2E 00 65 00 78 00 65}
		$op1 = {55 8B EC 83 EC 10 B9 B5 04 00 00 53 56 8B 75 08 C1 E6 10 33 75 08 81 F6 CD 8E CD 99 8B C6 C1 E8 15 57 3B C1}
		$op2 = {55 8B EC 83 EC 44 56 8B 75 14 85 F6 0F 84 [4] 53 8B 5D 10 8D 4D BC 8B C3 2B C1 89 45 14}

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 2 of them or 4 of them
}
