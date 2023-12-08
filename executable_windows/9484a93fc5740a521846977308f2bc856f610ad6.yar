import "pe"

rule RooterCode : Rooter Family
{
	meta:
		description = "Rooter code features"
		author = "Seth Hardy"
		last_modified = "2014-07-10"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 80 B0 ?? ?? ?? ?? 30 40 3D 00 50 00 00 7C F1 }

	condition:
		any of them
}
