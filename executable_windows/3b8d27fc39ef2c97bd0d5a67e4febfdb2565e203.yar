rule Windows_Trojan_Generic_40899c85
{
	meta:
		author = "Elastic Security"
		id = "40899c85-bb49-412c-8081-3a1359957c52"
		fingerprint = "d02a17a3b9efc2fd991320a5db7ab2384f573002157cddcd12becf137e893bd8"
		creation_date = "2023-12-15"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "88eb4f2e7085947bfbd03c69573fdca0de4a74bab844f09ecfcf88e358af20cc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic"
		filetype = "executable"

	strings:
		$a1 = "_sqlDataTypeSize"
		$a2 = "ChromeGetName"
		$a3 = "get_os_crypt"

	condition:
		all of them
}
