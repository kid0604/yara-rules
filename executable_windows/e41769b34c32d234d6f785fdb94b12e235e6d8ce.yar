import "pe"

rule AsCryptv01SToRM2
{
	meta:
		author = "malware-lu"
		description = "Detects AsCryptv01SToRM2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 [3] 83 [4] 90 90 90 83 [2] E2 }

	condition:
		$a0
}
