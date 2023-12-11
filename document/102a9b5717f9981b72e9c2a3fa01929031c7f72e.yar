rule suspicious_launch_action : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		description = "Detects suspicious launch actions in PDF files"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/OpenAction/
		$attrib4 = /\/F /

	condition:
		$magic in (0..1024) and 3 of ($attrib*)
}
