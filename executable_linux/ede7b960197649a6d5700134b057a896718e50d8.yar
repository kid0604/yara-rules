rule Linux_Trojan_Gafgyt_d608cf3b
{
	meta:
		author = "Elastic Security"
		id = "d608cf3b-c255-4a8d-9bf1-66f92eacd751"
		fingerprint = "3825aa1c9cddb46fdef6abc0503b42acbca8744dd89b981a3eea8db2f86a8a76"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { FF 2F E1 7E 03 00 00 78 D8 00 00 24 00 00 00 28 00 00 00 4C }

	condition:
		all of them
}
