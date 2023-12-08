import "pe"

rule NsPackV2XLiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NsPackV2XLiuXingPing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6E 73 70 61 63 6B 24 40 }

	condition:
		$a0
}
