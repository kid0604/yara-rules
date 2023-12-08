rule Windows_Trojan_ShadowPad_be71209d
{
	meta:
		author = "Elastic Security"
		id = "be71209d-b1c0-4922-87ae-47d0930d8755"
		fingerprint = "629f1502ce9f429ba6d497b8f2b0b35e57ca928a764ee6f3cb43521bfa6b5af4"
		creation_date = "2023-01-31"
		last_modified = "2023-02-01"
		description = "Target ShadowPad loader"
		threat_name = "Windows.Trojan.ShadowPad"
		reference_sample = "452b08d6d2aa673fb6ccc4af6cebdcb12b5df8722f4d70d1c3491479e7b39c05"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "{%8.8x-%4.4x-%4.4x-%8.8x%8.8x}"

	condition:
		all of them
}
