import "pe"

rule FakeNinjav28Spirit
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of FakeNinjav28Spirit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA [4] FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }

	condition:
		$a0
}
