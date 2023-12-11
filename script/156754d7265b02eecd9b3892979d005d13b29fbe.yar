rule hex_script
{
	meta:
		description = "Detects the presence of a hex encoded script"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "\\x73\\x63\\x72\\x69\\x70\\x74\\x22"

	condition:
		any of them and filesize <500KB
}
