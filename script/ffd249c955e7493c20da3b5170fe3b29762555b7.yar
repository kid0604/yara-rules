import "pe"

rule SUSP_Command_Line_Combos_Feb24_2 : SCRIPT
{
	meta:
		description = "Detects suspicious command line combinations often found in post exploitation activities"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		date = "2024-02-23"
		score = 75
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sa1 = " | iex"
		$sa2 = "iwr -UseBasicParsing "

	condition:
		filesize <2MB and all of them
}
