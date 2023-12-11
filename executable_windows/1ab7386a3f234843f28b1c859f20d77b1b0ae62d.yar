import "pe"

private rule RemoteStrings : Remote Variant Surtr Family
{
	meta:
		description = "indicators for remote.dll - surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\x00Remote.dll\x00"
		$ = "\x00CGm_PlugBase::"
		$ = "\x00ServiceMain\x00_K_H_K_UH\x00"
		$ = "\x00_Remote_\x00" wide

	condition:
		any of them
}
