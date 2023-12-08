rule Windows_Trojan_NapListener_414180a7
{
	meta:
		author = "Elastic Security"
		id = "414180a7-ca8d-4cf8-a346-08c3e0e1ed8a"
		fingerprint = "460b21638f200bf909e9e47bc716acfcb323540fbaa9ea9d0196361696ffa294"
		creation_date = "2023-02-28"
		last_modified = "2023-03-20"
		threat_name = "Windows.Trojan.NapListener"
		reference_sample = "6e8c5bb2dfc90bca380c6f42af7458c8b8af40b7be95fab91e7c67b0dee664c4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan NapListener"
		filetype = "executable"

	strings:
		$a1 = "https://*:443/ews/MsExgHealthCheckd/" ascii wide
		$a2 = "FillFromEncodedBytes" ascii wide
		$a3 = "Exception caught" ascii wide
		$a4 = "text/html; charset=utf-8" ascii wide
		$a5 = ".Run" ascii wide
		$a6 = "sdafwe3rwe23" ascii wide

	condition:
		5 of them
}
