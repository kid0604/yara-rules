rule Windows_Exploit_FakePipe_6bc93551
{
	meta:
		author = "Elastic Security"
		id = "6bc93551-b528-464b-8f1f-06db58c1cb01"
		fingerprint = "e2e31171486ee71bff9450966ba7b68dd0013856f1bda9ff7a30270855332c44"
		creation_date = "2024-02-28"
		last_modified = "2024-03-21"
		threat_name = "Windows.Exploit.FakePipe"
		reference_sample = "545a41ccfcd0a4f09c1c62bef2dde61b52fa92abada71ab72b3f4febb9265f75"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows exploit FakePipe"
		filetype = "executable"

	strings:
		$api = "ImpersonateNamedPipeClient"
		$s1 = "\\\\.\\pipe\\%ws\\pipe\\" wide nocase
		$s2 = "\\\\.\\pipe\\%s\\pipe\\" wide nocase
		$s3 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 00 19 5C 00 70 00 69 00 70 00 65 00 5C }

	condition:
		$api and any of ($s*)
}