rule Windows_Trojan_Formbook_772cc62d
{
	meta:
		author = "Elastic Security"
		id = "772cc62d-345c-42d8-97ab-f67e447ddca4"
		fingerprint = "3d732c989df085aefa1a93b38a3c078f9f0c3ee214292f6c1e31a9fc1c9ae50e"
		creation_date = "2022-05-23"
		last_modified = "2022-07-18"
		threat_name = "Windows.Trojan.Formbook"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Formbook variant 772cc62d"
		filetype = "executable"

	strings:
		$a1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
		$a2 = "signin"
		$a3 = "persistent"
		$r1 = /.\:\\Users\\[^\\]{1,50}\\AppData\\Roaming\\[a-zA-Z0-9]{8}\\[a-zA-Z0-9]{3}log\.ini/ wide

	condition:
		2 of ($a*) and $r1
}
