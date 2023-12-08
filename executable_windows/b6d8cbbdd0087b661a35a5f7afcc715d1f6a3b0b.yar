import "pe"

rule ASProtectv12xNewStrain
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.2x New Strain malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 01 [3] E8 01 [3] C3 C3 }

	condition:
		$a0 at pe.entry_point
}
