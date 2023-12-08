import "pe"

rule SafeNetCode : SafeNet Family
{
	meta:
		description = "SafeNet code features"
		author = "Seth Hardy"
		last_modified = "2014-07-16"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 83 C7 14 81 FF F8 D0 40 00 }

	condition:
		any of them
}
