rule DestructiveTargetCleaningTool7
{
	meta:
		description = "Detects a destructive target cleaning tool"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "SetFilePointer"
		$b = "SetEndOfFile"
		$c = {75 17 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 ff D5 56 ff 15 ?? ?? ?? ?? 56}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}
