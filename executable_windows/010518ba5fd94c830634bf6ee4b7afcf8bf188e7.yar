import "pe"

rule nAspyUpdateCode : nAspyUpdate Family
{
	meta:
		description = "nAspyUpdate code features"
		author = "Seth Hardy"
		last_modified = "2014-07-14"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }

	condition:
		any of them
}
