rule Windows_Rootkit_R77_99050e7d
{
	meta:
		author = "Elastic Security"
		id = "99050e7d-b9b2-411f-b315-0ac7f556314c"
		fingerprint = "1fa724556616eed4adfe022602795ffc61fe64dd910b5b83fd7610933b79d71f"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Rootkit.R77"
		reference_sample = "3dc94c88caa3169e096715eb6c2e6de1b011120117c0a51d12f572b4ba999ea6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Rootkit.R77"
		filetype = "executable"

	strings:
		$a1 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 24 00 37 00 37 00 63 00 68 00 69 00 6C 00 64 00 70 00 72 00 6F 00 63 00 36 00 34 00 }
		$a2 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 24 00 37 00 37 00 63 00 68 00 69 00 6C 00 64 00 70 00 72 00 6F 00 63 00 33 00 32 00 }

	condition:
		all of them
}
