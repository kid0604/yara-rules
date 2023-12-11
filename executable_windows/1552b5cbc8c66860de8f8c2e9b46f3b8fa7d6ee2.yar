rule Windows_Trojan_Emotet_d6ac1ea4
{
	meta:
		author = "Elastic Security"
		id = "d6ac1ea4-b0a8-4023-b712-9f4f2c7146a3"
		fingerprint = "7e6224c58c283765b5e819eb46814c556ae6b7b5931cd1e3e19ca3ec8fa31aa2"
		creation_date = "2022-05-24"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.Emotet"
		reference_sample = "2c6709d5d2e891d1ce26fdb4021599ac10fea93c7773f5c00bea8e5e90404b71"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Emotet variant with specific strings"
		filetype = "executable"

	strings:
		$calc1 = { C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? }
		$pre = { 48 83 EC ( 18 | 28 ) C7 44 24 ?? ?? ?? ?? ?? }
		$setup = { 48 8D 05 ?? ?? ?? ?? 48 89 81 ?? ?? ?? ?? }
		$post = { 8B 44 24 ?? 89 44 24 ?? 48 83 C4 18 C3 }

	condition:
		#calc1>=10 and #pre>=5 and #setup>=5 and #post>=5
}
