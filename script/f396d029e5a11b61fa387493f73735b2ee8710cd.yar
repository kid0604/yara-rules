rule md5_cdn_js_link_js
{
	meta:
		description = "Detects the presence of a specific JavaScript link in a file by its MD5 hash"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "grelos_v= null"

	condition:
		any of them
}
