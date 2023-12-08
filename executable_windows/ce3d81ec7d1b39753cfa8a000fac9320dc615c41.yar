import "pe"

rule ActiveMARKTMR5311140Trymedia
{
	meta:
		author = "malware-lu"
		description = "Detects the ActiveMARKTMR5311140Trymedia malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25 }

	condition:
		$a0 at pe.entry_point
}
