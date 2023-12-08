rule Windows_Trojan_OnlyLogger_ec14d5f2
{
	meta:
		author = "Elastic Security"
		id = "ec14d5f2-5716-47f3-a7fb-98ec2d8679d1"
		fingerprint = "c69da3dfe0a464665759079207fbc0c82e690d812b38c83d3f4cd5998ecee1ff"
		creation_date = "2022-03-22"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.OnlyLogger"
		reference_sample = "f45adcc2aad5c0fd900df4521f404bc9ca71b01e3378a5490f5ae2f0c711912e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan OnlyLogger"
		filetype = "executable"

	strings:
		$a1 = "KILLME" ascii fullword
		$a2 = "%d-%m-%Y %H" ascii fullword
		$a3 = "/c taskkill /im \"" ascii fullword
		$a4 = "\" /f & erase \"" ascii fullword
		$a5 = "/info.php?pub=" ascii fullword

	condition:
		all of them
}
