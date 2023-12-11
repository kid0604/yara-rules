import "pe"

rule VxTrojanTelefoon
{
	meta:
		author = "malware-lu"
		description = "Detects VxTrojanTelefoon malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }

	condition:
		$a0 at pe.entry_point
}
