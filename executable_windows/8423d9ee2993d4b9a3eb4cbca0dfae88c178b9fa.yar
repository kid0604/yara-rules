import "pe"

rule OlyxCode : Olyx Family
{
	meta:
		description = "Olyx code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-19"
		os = "windows"
		filetype = "executable"

	strings:
		$six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
		$slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }

	condition:
		any of them
}
