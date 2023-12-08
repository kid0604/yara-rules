rule Windows_Trojan_CobaltStrike_9c0d5561
{
	meta:
		author = "Elastic Security"
		id = "9c0d5561-5b09-44ae-8e8c-336dee606199"
		fingerprint = "01d53fcdb320f0cd468a2521c3e96dcb0b9aa00e7a7a9442069773c6b3759059"
		creation_date = "2021-03-23"
		last_modified = "2021-10-04"
		description = "Identifies PowerShell Runner module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "PowerShellRunner.dll" wide fullword
		$a2 = "powershell.x64.dll" ascii fullword
		$a3 = "powershell.dll" ascii fullword
		$a4 = "\\\\.\\pipe\\powershell" ascii fullword
		$b1 = "PowerShellRunner.PowerShellRunner" ascii fullword
		$b2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
		$b3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
		$b4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
		$b5 = "CustomPSHostUserInterface" ascii fullword
		$b6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
		$b7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
		$c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
		$c2 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword

	condition:
		(1 of ($a*) and 4 of ($b*)) or 1 of ($c*)
}
