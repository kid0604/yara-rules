rule Windows_Trojan_RedLineStealer_983cd7a7
{
	meta:
		author = "Elastic Security"
		id = "983cd7a7-4e7b-413f-b859-b5cbfbf14ae6"
		fingerprint = "6dd74c3b67501506ee43340c07b53ddb94e919d27ad96f55eb4eff3de1470699"
		creation_date = "2024-03-27"
		last_modified = "2024-05-08"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "7aa20c57b8815dd63c8ae951e1819c75b5d2deec5aae0597feec878272772f35"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$decrypt_config_bytes = { 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 [0-6] 2A }
		$str1 = "net.tcp://" wide
		$str2 = "\\Discord\\Local Storage\\leveldb" wide

	condition:
		all of them
}
