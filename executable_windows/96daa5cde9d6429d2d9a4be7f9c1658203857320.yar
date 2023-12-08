import "pe"

rule disable_uax
{
	meta:
		author = "x0r"
		description = "Disable User Access Control"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
		$r1 = "UACDisableNotify"

	condition:
		all of them
}
