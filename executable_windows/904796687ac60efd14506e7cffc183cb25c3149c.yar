import "pe"

rule ACProtectV20risco
{
	meta:
		author = "malware-lu"
		description = "Detects ACProtect v2.0 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] 68 [4] C3 C3 }

	condition:
		$a0 at pe.entry_point
}
