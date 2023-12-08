rule Windows_Trojan_Trickbot_fd7a39af
{
	meta:
		author = "Elastic Security"
		id = "fd7a39af-c6ea-4682-a00a-01f775c3bb8d"
		fingerprint = "3f2e654f2ffdd940c27caec3faeb4bda24c797a17d0987378e36c1e16fadc772"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets wormDll64.dll module containing spreading functionality"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "D5BB8D94B71D475B5EB9BB4235A428563F4104EA49F11EF02C8A08D2E859FD68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "module64.dll" ascii fullword
		$a2 = "worming.png" wide
		$a3 = "Size - %d kB" ascii fullword
		$a4 = "[+] %s -" wide fullword
		$a5 = "%s\\system32" ascii fullword
		$a6 = "[-] %s" wide fullword
		$a7 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig>" ascii fullword
		$a8 = "*****MACHINE IN WORKGROUP*****" wide fullword
		$a9 = "*****MACHINE IN DOMAIN*****" wide fullword
		$a10 = "\\\\%s\\IPC$" ascii fullword
		$a11 = "Windows 5" ascii fullword
		$a12 = "InfMach" ascii fullword
		$a13 = "%s x64" wide fullword
		$a14 = "%s x86" wide fullword
		$a15 = "s(&(objectCategory=computer)(userAccountControl:" wide fullword
		$a16 = "------MACHINE IN D-N------" wide fullword

	condition:
		5 of ($a*)
}
