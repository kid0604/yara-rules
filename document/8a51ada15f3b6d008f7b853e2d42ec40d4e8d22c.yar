rule invalid_xref_numbers : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
		notes = "This can be also be in a stream..."
		weight = 1
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
		$reg1 = /endstream.*\r?\n?endobj.*\r?\n?startxref/

	condition:
		$magic in (0..1024) and not $reg0 and not $reg1
}
