rule Windows_Trojan_SourShark_f0247cce
{
	meta:
		author = "Elastic Security"
		id = "f0247cce-b983-41a1-9118-fd4c23e3d099"
		fingerprint = "174d6683890b855a06c672423b4a0b3aa291558d8a2af4771b931d186ce3cb63"
		creation_date = "2024-06-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Trojan.SourShark"
		reference_sample = "07eb88c69437ee6e3ea2fbab5f2fbd8e846125d18c1da7d72bb462e9d083c9fc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SourShark with specific strings"
		filetype = "executable"

	strings:
		$a1 = "%s\\svchost.%s"
		$a2 = "crypto_domain"
		$a3 = "postback_id"

	condition:
		all of them
}
