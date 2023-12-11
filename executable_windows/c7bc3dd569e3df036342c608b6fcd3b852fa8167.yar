import "pe"

rule APT9002Code
{
	meta:
		description = "9002 code features"
		author = "Seth Hardy"
		last_modified = "2014-06-25"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
		$ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }

	condition:
		any of them
}
