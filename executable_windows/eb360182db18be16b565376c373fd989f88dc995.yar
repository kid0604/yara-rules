import "pe"

rule SurtrStrings : Surtr Family
{
	meta:
		author = "Katie Kleemola"
		description = "Strings for Surtr"
		last_updated = "2014-07-16"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\x00soul\x00"
		$ = "\x00InstallDll.dll\x00"
		$ = "\x00_One.dll\x00"
		$ = "_Fra.dll"
		$ = "CrtRunTime.log"
		$ = "Prod.t"
		$ = "Proe.t"
		$ = "Burn\\"
		$ = "LiveUpdata_Mem\\"

	condition:
		any of them
}
