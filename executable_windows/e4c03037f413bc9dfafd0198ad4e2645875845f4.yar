rule SUSP_Reversed_Hacktool_Author : FILE
{
	meta:
		description = "Detects a suspicious path traversal into a Windows folder"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/"
		date = "2020-06-10"
		score = 65
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "iwiklitneg" fullword ascii wide
		$x2 = " eetbus@ " ascii wide

	condition:
		filesize <4000KB and 1 of them
}
