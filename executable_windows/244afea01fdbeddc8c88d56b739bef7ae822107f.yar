import "pe"

rule UnpackedBSSFXArchivev19
{
	meta:
		author = "malware-lu"
		description = "Detects an unpacked BSSFX archive version 19"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E 33 C0 50 B8 [2] 8E D8 FA 8E D0 BC [2] FB B8 [2] CD 21 3C 03 73 }

	condition:
		$a0 at pe.entry_point
}
