import "pe"

rule gh0st
{
	meta:
		author = "https://github.com/jackcr/"
		description = "Detects Gh0st RAT update"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 47 68 30 73 74 ?? ?? ?? ?? ?? ?? ?? ?? 78 9C }
		$b = "Gh0st Update"

	condition:
		any of them
}
