rule md5_0105d05660329704bdb0ecd3fd3a473b
{
	meta:
		description = "Detects suspicious code pattern often used in malware"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\)\s*\)\s*\{\s*eval\s*\(\s*\$\{/

	condition:
		any of them
}
