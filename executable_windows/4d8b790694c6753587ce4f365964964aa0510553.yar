import "pe"

rule RegSubDatCode : RegSubDat Family
{
	meta:
		description = "RegSubDat code features"
		author = "Seth Hardy"
		last_modified = "2014-07-14"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
		$ = { 68 FF FF 7F 00 5? }
		$ = { 68 FF 7F 00 00 5? }

	condition:
		all of them
}
