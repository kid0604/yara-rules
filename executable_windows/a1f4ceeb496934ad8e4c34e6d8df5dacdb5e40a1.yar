import "pe"

rule LURK0Header : Family LURK0
{
	meta:
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }

	condition:
		any of them
}
