import "pe"

rule nSpackV23LiuXingPing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of a specific string in a file, which may indicate potential malware activity"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 70 61 63 6B 24 40 }

	condition:
		$a0
}
