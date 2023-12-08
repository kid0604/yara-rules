import "pe"

rule wiper_encoded_strings
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		company = "novetta"
		description = "Detects encoded strings commonly used by wiper malware"
		os = "windows"
		filetype = "executable"

	strings:
		$scr = {89 D4 C4 D5 00 00 00}
		$explorer = {E2 DF D7 CB C8 D5 C2 D5 89 C2 DF C2 00 00 00 }
		$kernel32 = {CC C2 D5 C9 C2 CB 94 95  89 C3 CB CB 00 00 }

	condition:
		$scr or $explorer or $kernel32
}
