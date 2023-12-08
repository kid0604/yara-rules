import "pe"

rule PowerShell_Mal_HackTool_Gen
{
	meta:
		description = "Detects PowerShell hack tool samples - generic PE loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-11-02"
		hash1 = "d442304ca839d75b34e30e49a8b9437b5ab60b74d85ba9005642632ce7038b32"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "$PEBytes32 = 'TVqQAAMAAAAEAAAA" wide
		$x2 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword wide
		$x3 = "@($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword wide
		$x4 = "(Shellcode: LoadLibraryA.asm)" fullword wide

	condition:
		filesize <8000KB and 1 of them
}
