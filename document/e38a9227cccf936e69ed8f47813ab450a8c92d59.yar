rule suspicious_embed : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		description = "Detects suspicious PDF files with embedded content"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/

	condition:
		$magic in (0..1024) and 1 of ($meth*) and 2 of ($attrib*)
}
