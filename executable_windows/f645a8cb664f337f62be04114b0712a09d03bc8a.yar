import "pe"

rule INDICATOR_TOOL_SharpGhostTask
{
	meta:
		author = "ditekSHen"
		description = "Detects SharpGhostTask"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Ghosted" wide
		$x2 = /--target(binary|task)/ fullword wide
		$x3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\T" wide nocase
		$s4 = "__GhostTask|" ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}
