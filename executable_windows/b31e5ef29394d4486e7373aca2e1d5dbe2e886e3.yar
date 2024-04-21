rule Windows_Trojan_Generic_0e135d58
{
	meta:
		author = "Elastic Security"
		id = "0e135d58-efd9-4d5e-95d8-ddd597f8e6a8"
		fingerprint = "e1a9e0c4e5531ae4dd2962285789c3bb8bb2621aa20437384fc3abcc349718c6"
		creation_date = "2024-03-19"
		last_modified = "2024-03-19"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic with ID 0e135d58"
		filetype = "executable"

	strings:
		$a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }

	condition:
		1 of them
}
