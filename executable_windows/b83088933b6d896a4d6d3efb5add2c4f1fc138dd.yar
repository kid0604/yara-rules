import "pe"

rule SurtrCode : Surtr Family
{
	meta:
		author = "Katie Kleemola"
		description = "Code features for Surtr Stage1"
		last_updated = "2014-07-16"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 8A ?? ?? 84 ?? ?? 74 ?? 3C 01 74 ?? 34 01 88 41 3B ?? 72 ?? }
		$ = { C6 [3] 42 C6 [3] 75 C6 [3] 72 C6 [3] 6E C6 [3] 5C }
		$ = { C6 [3] 5F C6 [3] 46 C6 [3] 69 C6 [3] 72 C6 [3] 65 C6 [3] 2E C6 [3] 64 }

	condition:
		any of them
}
