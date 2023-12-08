import "pe"

rule anti_dbg
{
	meta:
		author = "x0r"
		description = "Checks if being debugged"
		version = "0.2"
		os = "windows"
		filetype = "executable"

	strings:
		$d1 = "Kernel32.dll" nocase
		$c1 = "CheckRemoteDebuggerPresent"
		$c2 = "IsDebuggerPresent"
		$c3 = "OutputDebugString"
		$c4 = "ContinueDebugEvent"
		$c5 = "DebugActiveProcess"

	condition:
		$d1 and 1 of ($c*)
}
