rule eval_with_comments
{
	meta:
		description = "Detects the use of eval function with comments"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /(^|\s)eval\s*\/\*.{,128}\*\/\s*\(/

	condition:
		any of them and filesize <500KB
}
