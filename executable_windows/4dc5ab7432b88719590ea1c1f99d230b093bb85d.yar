import "pe"

rule PuNkMoD1xPuNkDuDe
{
	meta:
		author = "malware-lu"
		description = "Detects PuNkMoD1xPuNkDuDe malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 94 B9 [2] 00 00 BC [4] 80 34 0C }

	condition:
		$a0
}
