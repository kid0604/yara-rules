import "pe"

rule AsCryptv01SToRM1
{
	meta:
		author = "malware-lu"
		description = "Detects AsCryptv01SToRM1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 81 [6] 83 [7] 83 [2] E2 ?? EB }

	condition:
		$a0
}
