rule glassrat_alt_1 : RAT
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		description = "Detects GlassRat RAT activity"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "PostQuitMessage"
		$b = "pwlfnn10,gzg"
		$c = "update.dll"
		$d = "_winver"

	condition:
		all of them
}
