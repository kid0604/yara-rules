import "pe"

rule HKTL_SqlMap
{
	meta:
		description = "Detects sqlmap hacktool"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/sqlmapproject/sqlmap"
		date = "2018-10-09"
		hash1 = "9444478b03caf7af853a64696dd70083bfe67f76aa08a16a151c00aadb540fa8"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "if cmdLineOptions.get(\"sqlmapShell\"):" fullword ascii
		$x2 = "if conf.get(\"dumper\"):" fullword ascii

	condition:
		filesize <50KB and 1 of them
}
