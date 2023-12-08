import "pe"

rule EnfalCode : Enfal Family
{
	meta:
		description = "Enfal code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-19"
		os = "windows"
		filetype = "executable"

	strings:
		$decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }

	condition:
		any of them
}
