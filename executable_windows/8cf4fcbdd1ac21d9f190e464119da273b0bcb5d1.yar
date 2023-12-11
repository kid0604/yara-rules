import "pe"

rule APT3102Strings
{
	meta:
		description = "3102 Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "rundll32_exec.dll\x00Update"

	condition:
		any of them
}
