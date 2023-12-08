import "pe"

rule aPackv098bJibz
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of aPackv098bJibz malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 93 07 1F 05 [2] 8E D0 BC [2] EA }

	condition:
		$a0
}
