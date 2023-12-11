import "pe"

rule muckisprotectorImucki
{
	meta:
		author = "malware-lu"
		description = "Detects the MuckisProtectorImucki malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [4] B9 [4] 8A 06 F6 D0 88 06 46 E2 F7 E9 }

	condition:
		$a0 at pe.entry_point
}
