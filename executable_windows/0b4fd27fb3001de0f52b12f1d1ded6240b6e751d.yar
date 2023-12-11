import "pe"

rule disable_antivirus
{
	meta:
		author = "x0r"
		description = "Disable AntiVirus"
		version = "0.2"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
		$p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
		$p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase
		$c1 = "RegSetValue"
		$r1 = "AntiVirusDisableNotify"
		$r2 = "DontReportInfectionInformation"
		$r3 = "DisableAntiSpyware"
		$r4 = "RunInvalidSignatures"
		$r5 = "AntiVirusOverride"
		$r6 = "CheckExeSignatures"
		$f1 = "blackd.exe" nocase
		$f2 = "blackice.exe" nocase
		$f3 = "lockdown.exe" nocase
		$f4 = "lockdown2000.exe" nocase
		$f5 = "taskkill.exe" nocase
		$f6 = "tskill.exe" nocase
		$f7 = "smc.exe" nocase
		$f8 = "sniffem.exe" nocase
		$f9 = "zapro.exe" nocase
		$f10 = "zlclient.exe" nocase
		$f11 = "zonealarm.exe" nocase

	condition:
		($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}
