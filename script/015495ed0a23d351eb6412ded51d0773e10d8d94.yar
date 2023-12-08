rule CmdAsp_asp
{
	meta:
		description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "64f24f09ec6efaa904e2492dffc518b9"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "CmdAsp.asp"
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s2 = "-- Use a poor man's pipe ... a temp file --"
		$s3 = "maceo @ dogmile.com"

	condition:
		2 of them
}
