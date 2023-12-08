rule MacOS_Trojan_Metasploit_65a2394b
{
	meta:
		author = "Elastic Security"
		id = "65a2394b-0e66-4cb5-b6aa-3909120f0a94"
		fingerprint = "082da76eb8da9315d495b79466366367f19170f93c0a29966858cb92145e38d7"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit stages vforkshell.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/osx/x86/vforkshell.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "executable"

	strings:
		$a1 = { 31 DB 83 EB 01 43 53 57 53 B0 5A CD 80 72 43 83 }

	condition:
		all of them
}
