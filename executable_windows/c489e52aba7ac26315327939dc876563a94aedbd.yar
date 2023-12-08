import "pe"

rule CCTV0Header : Family CCTV0
{
	meta:
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { C6 [5] 43 C6 [5] 43 C6 [5] 54 C6 [5] 56 C6 [5] 30 }
		$ = { B0 43 88 [3] 88 [3] C6 [3] 54 C6 [3] 56 [0-12] (B0 30 | C6 [3] 30) }

	condition:
		any of them
}
