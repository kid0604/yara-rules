rule possible_exploit : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		description = "Detects possible exploit in PDF files"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/
		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		$nop = "%u9090%u9090"

	condition:
		$magic in (0..1024) and (2 of ($attrib*)) or ($action0 and #shell>10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}
