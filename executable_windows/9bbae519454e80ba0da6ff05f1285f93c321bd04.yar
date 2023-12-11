import "pe"

rule ORiENV1XV2XFisunAV
{
	meta:
		author = "malware-lu"
		description = "Detects ORiEN executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D }

	condition:
		$a0
}
