import "pe"

rule MongalCode
{
	meta:
		description = "Mongal code features"
		author = "Seth Hardy"
		last_modified = "2014-07-15"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }

	condition:
		any of them
}
