import "pe"

private rule RSharedStrings : Surtr Family
{
	meta:
		description = "identifiers for remote and gmremote"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "nView_DiskLoydb" wide
		$ = "nView_KeyLoydb" wide
		$ = "nView_skins" wide
		$ = "UsbLoydb" wide
		$ = "%sBurn%s" wide
		$ = "soul" wide

	condition:
		any of them
}
