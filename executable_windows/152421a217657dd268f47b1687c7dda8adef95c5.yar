import "pe"

rule WimmieShellcode : Wimmie Family
{
	meta:
		description = "Wimmie code features"
		author = "Seth Hardy"
		last_modified = "2014-07-17"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
		$xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }

	condition:
		any of them
}
