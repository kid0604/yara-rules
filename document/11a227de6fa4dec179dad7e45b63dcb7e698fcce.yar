rule EXPL_MAL_MalDoc_OBFUSCT_MHTML_Sep21_1
{
	meta:
		description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
		date = "2021-09-18"
		score = 90
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		os = "windows"
		filetype = "document"

	strings:
		$h1 = "<?xml " ascii wide
		$s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii wide

	condition:
		filesize <25KB and all of them
}
