rule Windows_Trojan_Trickbot_01365e46
{
	meta:
		author = "Elastic Security"
		id = "01365e46-c769-4c6e-913a-4d1e42948af2"
		fingerprint = "98505c3418945c10bf4f50a183aa49bdbc7c1c306e98132ae3d0fc36e216f191"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "5c450d4be39caef1d9ec943f5dfeb6517047175fec166a52970c08cd1558e172"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant"
		filetype = "executable"

	strings:
		$a = { 8B 43 28 4C 8B 53 18 4C 8B 5B 10 4C 8B 03 4C 8B 4B 08 89 44 24 38 48 89 4C 24 30 4C }

	condition:
		all of them
}
