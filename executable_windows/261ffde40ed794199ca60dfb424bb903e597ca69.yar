import "pe"

rule LameCryptv10
{
	meta:
		author = "malware-lu"
		description = "Detects LameCryptv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 66 9C BB [4] 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }

	condition:
		$a0 at pe.entry_point
}
