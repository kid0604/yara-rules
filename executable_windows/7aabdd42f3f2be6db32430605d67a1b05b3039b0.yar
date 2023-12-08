import "pe"

rule HaspdongleAlladin
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Aladdin HASP dongle related code in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 53 51 52 57 56 8B 75 1C 8B 3E [5] 8B 5D 08 8A FB [2] 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32 }

	condition:
		$a0 at pe.entry_point
}
