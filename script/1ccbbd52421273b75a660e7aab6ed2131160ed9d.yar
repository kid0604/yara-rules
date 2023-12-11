rule gate_php_js
{
	meta:
		description = "Detects gate.php URL with token and host parameters"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\/gate.php\?token=.{,10}&host=/

	condition:
		any of them
}
