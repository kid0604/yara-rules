rule multiple_versions : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"
		weight = 1
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$s0 = "trailer"
		$s1 = "%%EOF"

	condition:
		$magic in (0..1024) and #s0>1 and #s1>1
}
