rule apt3_bemstour_implant_byte_patch
{
	meta:
		description = "Detects an implant used by Bemstour exploitation tool (APT3)"
		author = "Mark Lechtik"
		company = "Check Point Software Technologies LTD."
		date = "2019-06-25"
		sha256 = "0b28433a2b7993da65e95a45c2adf7bc37edbd2a8db717b85666d6c88140698a"
		os = "windows"
		filetype = "executable"

	strings:
		$chunk_1 = {

C7 45 ?? 55 8B EC 83
C7 45 ?? EC 74 53 56
C7 45 ?? 8B 75 08 33
C7 45 ?? C9 57 C7 45
C7 45 ?? 8C 4C 6F 61

}

	condition:
		any of them
}
