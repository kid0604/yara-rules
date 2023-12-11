import "pe"

rule PrivateExeProtector1xsetisoft
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting PrivateExeProtector1xsetisoft malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 [3] C3 }

	condition:
		$a0 at pe.entry_point
}
