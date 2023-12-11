import "pe"

rule Insta11Code : Insta11 Family
{
	meta:
		description = "Insta11 code features"
		author = "Seth Hardy"
		last_modified = "2014-06-23"
		os = "windows"
		filetype = "executable"

	strings:
		$jumpandpush = { E9 00 00 00 00 68 23 04 00 00 }

	condition:
		any of them
}
