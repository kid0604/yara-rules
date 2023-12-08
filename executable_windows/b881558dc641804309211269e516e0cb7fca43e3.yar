import "pe"

rule iexpl0reCode : iexpl0ree Family
{
	meta:
		description = "iexpl0re code features"
		author = "Seth Hardy"
		last_modified = "2014-07-21"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
		$ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
		$ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
		$ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
		$ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
		$ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }

	condition:
		any of them
}
