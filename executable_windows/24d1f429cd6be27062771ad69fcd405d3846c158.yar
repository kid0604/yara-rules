import "pe"

rule cxpidCode
{
	meta:
		description = "cxpid code features"
		author = "Seth Hardy"
		last_modified = "2014-06-23"
		os = "windows"
		filetype = "executable"

	strings:
		$entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }

	condition:
		any of them
}
