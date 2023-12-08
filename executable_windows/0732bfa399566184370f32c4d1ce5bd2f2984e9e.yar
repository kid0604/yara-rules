rule Windows_Trojan_DownTown_145ecd2f
{
	meta:
		author = "Elastic Security"
		id = "145ecd2f-d012-4566-a2e9-696cdbd793ce"
		fingerprint = "d755ad4a24b390ce56d4905e40cec83a39ea515cfbe7e1a534950ca858343e70"
		creation_date = "2023-08-23"
		last_modified = "2023-09-20"
		threat_name = "Windows.Trojan.DownTown"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan DownTown"
		filetype = "executable"

	strings:
		$a1 = "DeletePluginObject"
		$a2 = "GetPluginInfomation"
		$a3 = "GetPluginObject"
		$a4 = "GetRegisterCode"

	condition:
		all of them
}
