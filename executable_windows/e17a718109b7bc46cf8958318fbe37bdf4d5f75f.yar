rule Windows_Trojan_Diceloader_15eeb7b9
{
	meta:
		author = "Elastic Security"
		id = "15eeb7b9-311f-477b-8ae1-b8f689a154b7"
		fingerprint = "4cc70bec5d241c6f84010fbfe2eafbc6ec6d753df2bb3f52d9498b54b11fc8cb"
		creation_date = "2021-04-23"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Diceloader"
		reference_sample = "a1202df600d11ad2c61050e7ba33701c22c2771b676f54edd1846ef418bea746"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Diceloader variant with ID 15eeb7b9"
		filetype = "executable"

	strings:
		$a1 = { E9 92 9D FF FF C3 E8 }
		$a2 = { E9 E8 61 FF FF C3 E8 }

	condition:
		any of them
}
