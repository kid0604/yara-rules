rule Sandboxie_Detection : AntiVM
{
	meta:
		description = "Looks for Sandboxie presence"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		os = "windows"
		filetype = "executable"

	strings:
		$sbie = "SbieDll.dll" nocase wide ascii
		$buster = /LOG_API(_VERBOSE)?.DLL/ nocase wide ascii
		$sbie_process_1 = "SbieSvc.exe" nocase wide ascii
		$sbie_process_2 = "SbieCtrl.exe" nocase wide ascii
		$sbie_process_3 = "SandboxieRpcSs.exe" nocase wide ascii
		$sbie_process_4 = "SandboxieDcomLaunch.exe" nocase wide ascii
		$sbie_process_5 = "SandboxieCrypto.exe" nocase wide ascii
		$sbie_process_6 = "SandboxieBITS.exe" nocase wide ascii
		$sbie_process_7 = "SandboxieWUAU.exe" nocase wide ascii

	condition:
		any of them
}
