rule Windows_Trojan_Netwire_f42cb379
{
	meta:
		author = "Elastic Security"
		id = "f42cb379-ac8c-4790-a6d3-aad6dc4acef6"
		fingerprint = "a52d2be082d57d07ab9bb9087dd258c29ef0528c4207ac6b31832f975a1395b6"
		creation_date = "2022-08-14"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Netwire"
		reference_sample = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Netwire with specific strings"
		filetype = "executable"

	strings:
		$a1 = "http://%s%ComSpec" ascii fullword
		$a2 = "%c%.8x%s" ascii fullword
		$a3 = "%6\\6Z65dlNh\\YlS.dfd" ascii fullword
		$a4 = "GET %s HTTP/1.1" ascii fullword
		$a5 = "R-W65: %6:%S" ascii fullword
		$a6 = "PTLLjPq %6:%S -qq9/G.y" ascii fullword

	condition:
		4 of them
}
