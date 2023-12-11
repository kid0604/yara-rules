import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_IExecuteCommandCOM
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding command execution via IExecuteCommand COM object"
		os = "windows"
		filetype = "executable"

	strings:
		$r1 = "Classes\\Folder\\shell\\open\\command" ascii wide nocase
		$k1 = "DelegateExecute" ascii wide
		$s1 = "/EXEFilename \"{0}" ascii wide
		$s2 = "/WindowState \"\"" ascii wide
		$s3 = "/PriorityClass \"\"32\"\" /CommandLine \"" ascii wide
		$s4 = "/StartDirectory \"" ascii wide
		$s5 = "/RunAs" ascii wide

	condition:
		uint16(0)==0x5a4d and ((1 of ($r*) and 1 of ($k*)) or ( all of ($s*)))
}
