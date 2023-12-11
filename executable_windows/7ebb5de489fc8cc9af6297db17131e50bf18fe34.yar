import "pe"

rule WarpCode : Warp Family
{
	meta:
		description = "Warp code features"
		author = "Seth Hardy"
		last_modified = "2014-07-10"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 80 38 2B 75 03 C6 00 2D 80 38 2F 75 03 C6 00 5F }

	condition:
		any of them
}
