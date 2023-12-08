rule Empire_Invoke_Mimikatz_alt_1
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Mimikatz.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "c5481864b757837ecbc75997fa24978ffde3672b8a144a55478ba9a864a19466"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwc" ascii
		$s2 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)" fullword ascii
		$s3 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii

	condition:
		filesize <2500KB and 2 of them
}
