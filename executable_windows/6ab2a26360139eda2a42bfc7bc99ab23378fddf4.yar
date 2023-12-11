import "pe"

rule YayihCode : Yayih Family
{
	meta:
		description = "Yayih code features"
		author = "Seth Hardy"
		last_modified = "2014-07-11"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }

	condition:
		any of them
}
