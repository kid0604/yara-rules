rule LOG_SUSP_WEBSHELL_Cmd_Indicator_Apr25
{
	meta:
		description = "Detects a pattern which is often related to web shell activity"
		reference = "https://regex101.com/r/N6oZ2h/2"
		author = "Florian Roth"
		date = "2025-04-25"
		score = 50
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$xr01 = /\.(asp|aspx|jsp|php)\?cmd=[a-z0-9%+\-]{3,20} HTTP\/1\.[01]["']? 200/

	condition:
		1 of them
}
