rule INDICATOR_TOOL_HFS_WebServer
{
	meta:
		author = "ditekSHen"
		description = "Detects HFS Web Server"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SOFTWARE\\Borland\\Delphi\\" ascii
		$s2 = "C:\\code\\mine\\hfs\\scriptLib.pas" fullword ascii
		$s3 = "hfs.*;*.htm*;descript.ion;*.comment;*.md5;*.corrupted;*.lnk" ascii
		$s4 = "Server: HFS" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
