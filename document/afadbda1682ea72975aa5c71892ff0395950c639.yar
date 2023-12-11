rule multiple_filtering : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.2"
		weight = 3
		description = "Detects PDF files with multiple filters applied"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/

	condition:
		$magic in (0..1024) and $attrib
}
