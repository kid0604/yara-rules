import "pe"

rule PEProtect09byCristophGabler1998
{
	meta:
		author = "malware-lu"
		description = "Detects PEProtect version 0.9 by Cristoph Gabler 1998"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }

	condition:
		$a0
}
