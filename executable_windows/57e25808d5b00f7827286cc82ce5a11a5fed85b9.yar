rule Windows_Trojan_Smokeloader_de52ed44
{
	meta:
		author = "Elastic Security"
		id = "de52ed44-062c-4b0d-9a41-1bfc31a8daa9"
		fingerprint = "950db8f87a81ef05cc2ecbfa174432ab31a3060c464836f3b38448bd8e5801be"
		creation_date = "2023-05-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Smokeloader"
		reference_sample = "c689a384f626616005d37a94e6a5a713b9eead1b819a238e4e586452871f6718"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan Smokeloader"
		filetype = "executable"

	strings:
		$a1 = { 08 31 FF 89 7D CC 66 8C E8 66 85 C0 74 03 FF 45 CC FF 53 48 }
		$a2 = { B0 8F 45 C8 8D 45 B8 89 38 8D 4D C8 6A 04 57 6A 01 51 57 57 }

	condition:
		all of them
}
