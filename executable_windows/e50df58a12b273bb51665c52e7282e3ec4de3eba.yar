rule MAL_Backdoor_SPAREPART_SleepGenerator
{
	meta:
		author = "Mandiant"
		date = "2022-12-14"
		description = "Detects the algorithm used to determine the next sleep timer"
		version = "1"
		weight = "100"
		hash = "f9cd5b145e372553dded92628db038d8"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."
		reference = "https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government"
		os = "windows"
		filetype = "executable"

	strings:
		$ = {C1 E8 06 89 [5] C1 E8 02 8B}
		$ = {c1 e9 03 33 c1 [3] c1 e9 05 33 c1 83 e0 01}
		$ = {8B 80 FC 00 00 00}
		$ = {D1 E8 [4] c1 E1 0f 0b c1}

	condition:
		all of them
}
