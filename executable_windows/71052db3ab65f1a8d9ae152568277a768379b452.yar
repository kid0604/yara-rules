import "pe"

rule INDICATOR_TOOL_Pandora
{
	meta:
		author = "ditekSHen"
		description = "Detects Pandora tool to extract credentials from password managers"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "process PID:" fullword wide
		$s2 = "Dump file created:" fullword wide
		$s3 = "System.Security.AccessControl.FileSystemAccessRule('Everyone', 'FullControl', 'Allow')" ascii
		$s4 = "{[math]::Round($_.PrivateMemorySize64" ascii
		$s5 = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $" ascii
		$s6 = "\"payload\":{\"logins\":" ascii
		$s7 = "\\pandora.pdb" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
