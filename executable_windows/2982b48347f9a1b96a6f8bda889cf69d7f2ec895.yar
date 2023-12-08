rule Windows_Trojan_Clipbanker_f9f9e79d
{
	meta:
		author = "Elastic Security"
		id = "f9f9e79d-ce71-4b6c-83e0-ac6e06252c25"
		fingerprint = "ec985e1273d8ff52ea7f86271a96db01633402facf8d140d11b82e5539e4b5fd"
		creation_date = "2022-04-23"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.Clipbanker"
		reference_sample = "0407e8f54490b2a24e1834d99ec0452f217499f1e5a64de3d28439d71d16d43c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Clipbanker with ID f9f9e79d"
		filetype = "executable"

	strings:
		$a1 = { 7E 7E 0F B7 04 77 83 F8 41 74 69 83 F8 42 74 64 83 F8 43 74 5F 83 }

	condition:
		all of them
}
