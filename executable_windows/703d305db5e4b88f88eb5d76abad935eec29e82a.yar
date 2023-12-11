import "pe"

rule APT28_CHOPSTICK
{
	meta:
		description = "Detects a malware that behaves like CHOPSTICK mentioned in APT28 report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/v3ebal"
		date = "2015-06-02"
		hash = "f4db2e0881f83f6a2387ecf446fcb4a4c9f99808"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "jhuhugit.tmp" fullword ascii
		$s8 = "KERNEL32.dll" fullword ascii
		$s9 = "IsDebuggerPresent" fullword ascii
		$s10 = "IsProcessorFeaturePresent" fullword ascii
		$s11 = "TerminateProcess" fullword ascii
		$s13 = "DeleteFileA" fullword ascii
		$s15 = "GetProcessHeap" fullword ascii
		$s16 = "!This program cannot be run in DOS mode." fullword ascii
		$s17 = "LoadLibraryA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <722KB and all of them
}
