rule Windows_Trojan_CobaltStrike_09b79efa
{
	meta:
		author = "Elastic Security"
		id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
		fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Invoke Assembly module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "invokeassembly.x64.dll" ascii fullword
		$a2 = "invokeassembly.dll" ascii fullword
		$b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
		$b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
		$b3 = "[-] Failed to create the runtime host" ascii fullword
		$b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
		$b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
		$b6 = "ReflectiveLoader"
		$b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
		$b8 = "[-] No .NET runtime found. :(" ascii fullword
		$b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
		$c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }

	condition:
		1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}
