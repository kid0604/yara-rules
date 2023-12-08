import "pe"

rule nBinderv40
{
	meta:
		author = "malware-lu"
		description = "Detects nBinder v4.0 executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5C 6E 62 34 5F 74 6D 70 5F 30 31 33 32 34 35 34 33 35 30 5C 00 00 00 00 00 00 00 00 00 E9 55 43 4C FF 01 1A 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79 }

	condition:
		$a0
}
