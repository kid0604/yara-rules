rule Windows_Trojan_SysJoker_34559bcd
{
	meta:
		author = "Elastic Security"
		id = "34559bcd-661a-4213-b896-2d7f882a16ef"
		fingerprint = "b1e01d0b94a60f6f5632a14d3d32f78bbe3049886ea3a3e838a29fb790a45918"
		creation_date = "2022-02-21"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.SysJoker"
		reference_sample = "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SysJoker"
		filetype = "executable"

	strings:
		$a1 = "\\txc1.txt\" && type \"" ascii fullword
		$a2 = "tempo1.txt" nocase
		$a3 = "user_token="
		$a4 = "{\"status\":\"success\",\"result\":\"" ascii fullword
		$a5 = "\",\"av\":\"" ascii fullword
		$a6 = "aSwpEHc0QyIxPRAqNmkeEwskMW8HODkkYRkCICIrJysHNmtlIzQiChMiGAxzQg==" ascii fullword
		$a7 = "ESQuBT8uQyglJy4QOicGXDMiayYtPQ==" ascii fullword

	condition:
		4 of them
}
