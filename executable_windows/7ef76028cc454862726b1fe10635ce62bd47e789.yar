import "pe"

rule PKZIPSFXv11198990
{
	meta:
		author = "malware-lu"
		description = "Detects PKZIPSFXv1.11 98990 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FC 2E 8C 0E [2] A1 [2] 8C CB 81 C3 [2] 3B C3 72 ?? 2D [2] 2D [2] FA BC [2] 8E D0 FB }

	condition:
		$a0 at pe.entry_point
}
