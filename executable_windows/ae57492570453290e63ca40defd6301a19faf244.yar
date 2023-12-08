rule Windows_Trojan_Remcos_7591e9f1
{
	meta:
		author = "Elastic Security"
		id = "7591e9f1-452d-4731-9bec-545fb0272c80"
		fingerprint = "9436c314f89a09900a9b3c2fd9bab4a0423912427cf47b71edce5eba31132449"
		creation_date = "2023-06-23"
		last_modified = "2023-07-10"
		threat_name = "Windows.Trojan.Remcos"
		reference_sample = "4e6e5ecd1cf9c88d536c894d74320c77967fe08c75066098082bf237283842fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Remcos"
		filetype = "executable"

	strings:
		$a1 = "ServRem" ascii fullword
		$a2 = "Screenshots" ascii fullword
		$a3 = "MicRecords" ascii fullword
		$a4 = "remcos.exe" wide nocase fullword
		$a5 = "Remcos" wide fullword
		$a6 = "logs.dat" wide fullword

	condition:
		3 of them
}
