rule js_splitting : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "These are commonly used to split up JS code"
		weight = 2
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$js = /\/JavaScript/
		$s0 = "getAnnots"
		$s1 = "getPageNumWords"
		$s2 = "getPageNthWord"
		$s3 = "this.info"

	condition:
		$magic in (0..1024) and $js and 1 of ($s*)
}
