import "pe"

rule anti_dbgtools
{
	meta:
		author = "x0r"
		description = "Checks for the presence of known debug tools"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "procexp.exe" nocase
		$f2 = "procmon.exe" nocase
		$f3 = "processmonitor.exe" nocase
		$f4 = "wireshark.exe" nocase
		$f5 = "fiddler.exe" nocase
		$f6 = "windbg.exe" nocase
		$f7 = "ollydbg.exe" nocase
		$f8 = "winhex.exe" nocase
		$f9 = "processhacker.exe" nocase
		$f10 = "hiew32.exe" nocase
		$c11 = "\\\\.\\NTICE"
		$c12 = "\\\\.\\SICE"
		$c13 = "\\\\.\\Syser"
		$c14 = "\\\\.\\SyserBoot"
		$c15 = "\\\\.\\SyserDbgMsg"

	condition:
		any of them
}
