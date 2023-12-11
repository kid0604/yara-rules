rule TrojanDownloader
{
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii
		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii
		$s5 = "SetConsoleMode" fullword ascii
		$s9 = "TerminateProcess" fullword ascii
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii

	condition:
		$x1 and $x2 and ( all of ($s*)) and filesize <35000
}
