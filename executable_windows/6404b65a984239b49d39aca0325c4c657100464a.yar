rule Windows_Trojan_Trickbot_5340afa3
{
	meta:
		author = "Elastic Security"
		id = "5340afa3-ff90-4f61-a1ac-aba1f32dd375"
		fingerprint = "7da4726ccda6a76d2da773d41f012763802d586f64a313c1c37733905ae9da81"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant 5340afa3"
		filetype = "executable"

	strings:
		$a = { E8 0C 89 5D F4 0F B7 DB 03 5D 08 66 83 F8 03 75 0A 8B 45 14 }

	condition:
		all of them
}
