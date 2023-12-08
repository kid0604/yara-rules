import "pe"

rule ExeLocker10IonIce
{
	meta:
		author = "malware-lu"
		description = "Detects the ExeLocker10IonIce malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
