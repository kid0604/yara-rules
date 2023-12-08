rule Windows_Trojan_Squirrelwaffle_88033ff1
{
	meta:
		author = "Elastic Security"
		id = "88033ff1-f9b1-4cdc-bb68-bd3a10027584"
		fingerprint = "94c0d8ce3e06cf02a6fb57c074ff0ef60346babcde43c61371d099b011d9fcf9"
		creation_date = "2021-09-20"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Squirrelwaffle"
		reference_sample = "00d045c89934c776a70318a36655dcdd77e1fedae0d33c98e301723f323f234c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Squirrelwaffle"
		filetype = "executable"

	strings:
		$a1 = "start /i /min /b start /i /min /b start /i /min /b " ascii fullword
		$a2 = " HTTP/1.1" ascii fullword
		$a3 = "Host:" ascii fullword
		$a4 = "APPDATA" ascii fullword

	condition:
		all of them
}
