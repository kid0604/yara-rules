import "pe"

rule ACProtectv135riscosoftwareIncAnticrackSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects ACProtect v1.35 by Risco Software Inc Anti-crack Software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [20] 55 53 45 52 33 32 2E 44 4C 4C 00 [33] 00 47 65 74 50 72 6F 63 }

	condition:
		$a0
}
