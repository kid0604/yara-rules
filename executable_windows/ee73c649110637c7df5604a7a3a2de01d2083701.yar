import "pe"

rule NetTravExports : NetTraveler Family
{
	meta:
		description = "Export names for dll component"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "?InjectDll@@YAHPAUHWND__@@K@Z"
		$ = "?UnmapDll@@YAHXZ"
		$ = "?g_bSubclassed@@3HA"

	condition:
		any of them
}
