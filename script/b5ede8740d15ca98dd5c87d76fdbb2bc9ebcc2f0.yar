rule MacOS_Trojan_Metasploit_f11ccdac
{
	meta:
		author = "Elastic Security"
		id = "f11ccdac-be75-4ba8-800a-179297a40792"
		fingerprint = "fbc1a5b77ed485706ae38f996cd086253ea1d43d963cb497446e5b0f3d0f3f11"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit shell_find_port.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_find_port.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { 50 6A 1F 58 CD 80 66 81 7F 02 04 D2 75 EE 50 }

	condition:
		all of them
}
