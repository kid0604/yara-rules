import "pe"

rule memory_pivy
{
	meta:
		author = "https://github.com/jackcr/"
		description = "Detects memory pivoting technique"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00}

	condition:
		any of them
}
