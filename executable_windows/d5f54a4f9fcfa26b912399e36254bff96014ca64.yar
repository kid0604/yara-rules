import "pe"

rule XPackv142
{
	meta:
		author = "malware-lu"
		description = "Detects XPackv142 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 72 ?? C3 8B DE 83 [2] C1 [2] 8C D8 03 C3 8E D8 8B DF 83 [2] C1 [2] 8C C0 03 C3 8E C0 C3 }

	condition:
		$a0
}
