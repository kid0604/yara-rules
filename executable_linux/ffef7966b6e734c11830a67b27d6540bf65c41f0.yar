rule Linux_Hacktool_Lightning_e87c9d50
{
	meta:
		author = "Elastic Security"
		id = "e87c9d50-dafc-45bd-8786-5df646108c8a"
		fingerprint = "22b982866241d50b6e5d964ee190f6d07982a5d3f0b2352d863c20432d5f785e"
		creation_date = "2022-11-08"
		last_modified = "2024-02-13"
		threat_name = "Linux.Hacktool.Lightning"
		reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
		reference_sample = "fd285c2fb4d42dde23590118dba016bf5b846625da3abdbe48773530a07bcd1e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Lightning"
		filetype = "executable"

	strings:
		$a1 = "Execute %s Faild." ascii fullword
		$a2 = "Lightning.Downloader" ascii fullword
		$a3 = "Execute %s Success." ascii fullword
		$a4 = "[-] Socks5 are Running!" ascii fullword
		$a5 = "[-] Get FileInfo(%s) Faild!" ascii fullword

	condition:
		all of them
}
