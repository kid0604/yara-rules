rule apt3_bemstour_implant_command_stack_variable
{
	meta:
		description = "Detecs an implant used by Bemstour exploitation tool (APT3)"
		author = "Mark Lechtik"
		company = "Check Point Software Technologies LTD."
		date = "2019-06-25"
		sha256 = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"
		os = "windows"
		filetype = "executable"

	strings:
		$chunk_1 = {

C7 85 ?? ?? ?? ?? 63 6D 64 2E
C7 85 ?? ?? ?? ?? 65 78 65 20
C7 85 ?? ?? ?? ?? 2F 63 20 63
C7 85 ?? ?? ?? ?? 6F 70 79 20
C7 85 ?? ?? ?? ?? 25 77 69 6E
C7 85 ?? ?? ?? ?? 64 69 72 25
C7 85 ?? ?? ?? ?? 5C 73 79 73
C7 85 ?? ?? ?? ?? 74 65 6D 33
C7 85 ?? ?? ?? ?? 32 5C 63 6D
C7 85 ?? ?? ?? ?? 64 2E 65 78
C7 85 ?? ?? ?? ?? 65 20 25 77
C7 85 ?? ?? ?? ?? 69 6E 64 69
C7 85 ?? ?? ?? ?? 72 25 5C 73
C7 85 ?? ?? ?? ?? 79 73 74 65
C7 85 ?? ?? ?? ?? 6D 33 32 5C
C7 85 ?? ?? ?? ?? 73 65 74 68
C7 85 ?? ?? ?? ?? 63 2E 65 78
C7 85 ?? ?? ?? ?? 65 20 2F 79
83 A5 ?? ?? ?? ?? 00
}
		$chunk_2 = {

C7 85 ?? ?? ?? ?? 63 6D 64 20
C7 85 ?? ?? ?? ?? 2F 63 20 22
C7 85 ?? ?? ?? ?? 6E 65 74 20
C7 85 ?? ?? ?? ?? 75 73 65 72
C7 85 ?? ?? ?? ?? 20 63 65 73
C7 85 ?? ?? ?? ?? 73 75 70 70
C7 85 ?? ?? ?? ?? 6F 72 74 20
C7 85 ?? ?? ?? ?? 31 71 61 7A
C7 85 ?? ?? ?? ?? 23 45 44 43
C7 85 ?? ?? ?? ?? 20 2F 61 64
C7 85 ?? ?? ?? ?? 64 20 26 26
C7 85 ?? ?? ?? ?? 20 6E 65 74
C7 85 ?? ?? ?? ?? 20 6C 6F 63
C7 85 ?? ?? ?? ?? 61 6C 67 72
C7 85 ?? ?? ?? ?? 6F 75 70 20
C7 85 ?? ?? ?? ?? 61 64 6D 69
C7 85 ?? ?? ?? ?? 6E 69 73 74
C7 85 ?? ?? ?? ?? 72 61 74 6F
C7 85 ?? ?? ?? ?? 72 73 20 63
C7 85 ?? ?? ?? ?? 65 73 73 75
C7 85 ?? ?? ?? ?? 70 70 6F 72
C7 85 ?? ?? ?? ?? 74 20 2F 61
C7 85 ?? ?? ?? ?? 64 64 22 00
6A 5C

}
		$chunk_3 = {

C7 45 ?? 57 69 6E 45
C7 45 ?? 78 65 63 00
C7 45 ?? 47 65 74 50
C7 45 ?? 72 6F 63 41
C7 45 ?? 64 64 72 65
C7 45 ?? 73 73 00 00
C7 45 ?? 43 72 65 61
C7 45 ?? 74 65 46 69
C7 45 ?? 6C 65 41 00
C7 45 ?? 57 72 69 74
C7 45 ?? 65 46 69 6C
C7 45 ?? 65 00 00 00
C7 45 ?? 43 6C 6F 73
C7 45 ?? 65 48 61 6E
C7 45 ?? 64 6C 65 00
89 4D ??

}

	condition:
		any of them
}