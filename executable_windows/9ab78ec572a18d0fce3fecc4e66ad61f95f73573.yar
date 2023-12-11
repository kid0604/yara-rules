rule Windows_Trojan_Smokeloader_4ee15b92
{
	meta:
		author = "Elastic Security"
		id = "4ee15b92-c62f-42d2-bbba-1dac2fa5644f"
		fingerprint = "5d2ed385c76dbb4c1c755ae88b68306086a199a25a29317ae132bc874b253580"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Smokeloader"
		reference_sample = "09b9283286463b35ea2d5abfa869110eb124eb8c1788eb2630480d058e82abf2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Smokeloader variant 4ee15b92"
		filetype = "executable"

	strings:
		$a = { 24 34 30 33 33 8B 45 F4 5F 5E 5B C9 C2 10 00 55 89 E5 83 EC }

	condition:
		all of them
}
