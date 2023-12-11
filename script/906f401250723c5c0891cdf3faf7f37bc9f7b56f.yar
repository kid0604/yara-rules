rule md5_87cf8209494eedd936b28ff620e28780
{
	meta:
		description = "Detects a specific string used in malicious scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "curl_close($cu);eval($o);};die();"

	condition:
		any of them
}
