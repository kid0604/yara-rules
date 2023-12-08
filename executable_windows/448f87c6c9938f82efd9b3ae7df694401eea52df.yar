rule Windows_Trojan_Trickbot_9d4d3fa4
{
	meta:
		author = "Elastic Security"
		id = "9d4d3fa4-4e37-40d7-8399-a49130b7ef49"
		fingerprint = "b06c3c7ba1f5823ce381971ed29554e5ddbe327b197de312738165ee8bf6e194"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant 9d4d3fa4"
		filetype = "executable"

	strings:
		$a = { 89 44 24 18 33 C9 89 44 24 1C 8D 54 24 38 89 44 24 20 33 F6 89 44 }

	condition:
		all of them
}
