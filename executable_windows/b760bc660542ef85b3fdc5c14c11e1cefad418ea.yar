rule CVE_2014_4076_Exploitcode
{
	meta:
		description = "Detects an exploit code for CVE-2014-4076"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Neo23x0/yarGen"
		date = "2018-04-04"
		hash1 = "44690af85efef2db04c7e8cba7ca0d0e53be1a1432a339570a7d26eec860b8ee"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[+] Created a new cmd.exe process" fullword ascii
		$x2 = "[+] Modified shellcode" fullword ascii
		$x3 = "[*] Spawning SYSTEM shell..." fullword ascii
		$x4 = "[*] MS14-070 (CVE-2014-4076) x86" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}
