import "pe"

rule nSpackV2xLiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of nSpackV2xLiuXingPing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }

	condition:
		$a0
}
