import "pe"

rule UPXModifierv01x
{
	meta:
		author = "malware-lu"
		description = "Detects modified UPX packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 BE [4] 8D BE [4] 57 83 CD }

	condition:
		$a0 at pe.entry_point
}
