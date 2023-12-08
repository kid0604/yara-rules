import "pe"

rule PEProtectv09
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect PEProtectv09 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 [4] 58 83 C0 07 C6 ?? C3 }
		$a1 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F }

	condition:
		$a0 at pe.entry_point or $a1
}
