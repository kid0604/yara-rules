import "pe"

rule VidgrabStrings : Vidgrab Family
{
	meta:
		description = "Vidgrab Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-20"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "IDI_ICON5" wide ascii
		$ = "starter.exe"
		$ = "wmifw.exe"
		$ = "Software\\rar"
		$ = "tmp092.tmp"
		$ = "temp1.exe"

	condition:
		3 of them
}
