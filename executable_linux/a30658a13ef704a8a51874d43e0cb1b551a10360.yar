rule Linux_Trojan_Gafgyt_e09726dc
{
	meta:
		author = "Elastic Security"
		id = "e09726dc-4e6d-4115-b178-d20375c09e04"
		fingerprint = "614d54b3346835cd5c2a36a54cae917299b1a1ae0d057e3fa1bb7dddefc1490f"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "1e64187b5e3b5fe71d34ea555ff31961404adad83f8e0bd1ce0aad056a878d73"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 00 00 48 83 EC 08 48 83 C4 08 C3 00 00 00 01 00 02 00 50 49 4E 47 }

	condition:
		all of them
}
