rule Windows_Trojan_Bazar_711d59f6
{
	meta:
		author = "Elastic Security"
		id = "711d59f6-6e8a-485d-b362-4c1bf1bda66e"
		fingerprint = "a9e78b4e39f4acaba86c2595db67fcdcd40d1af611d41a023bd5d8ca9804efa4"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Bazar"
		reference_sample = "f29253139dab900b763ef436931213387dc92e860b9d3abb7dcd46040ac28a0e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Bazar 711d59f6"
		filetype = "executable"

	strings:
		$a = { 0F 94 C3 41 0F 95 C0 83 FA 0A 0F 9C C1 83 FA 09 0F 9F C2 31 C0 }

	condition:
		all of them
}
