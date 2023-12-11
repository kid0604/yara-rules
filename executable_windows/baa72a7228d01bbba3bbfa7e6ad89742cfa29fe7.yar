import "pe"

rule MALWARE_Win_ShellcodeDLEI
{
	meta:
		author = "ditekSHen"
		description = "Detects shellcode downloader, executer, injector"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PPidSpoof" fullword ascii
		$s2 = "ProcHollowing" fullword ascii
		$s3 = "CreateProcess" fullword ascii
		$s4 = "DynamicCodeInject" fullword ascii
		$s5 = "PPIDDynCodeInject" fullword ascii
		$s6 = "MapAndStart" fullword ascii
		$s7 = "PPIDAPCInject" fullword ascii
		$s8 = "PPIDDLLInject" fullword ascii
		$s9 = "CopyShellcode" fullword ascii
		$s10 = "GetEntryFromBuffer" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 5 of ($s*)
}
