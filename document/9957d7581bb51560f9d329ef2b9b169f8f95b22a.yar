rule suspicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		description = "Detects PDF files with suspicious authors"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"

	condition:
		$magic in (0..1024) and $header and 1 of ($author*)
}
