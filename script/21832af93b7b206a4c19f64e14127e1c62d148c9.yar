rule md5_825a3b2a6abbe6abcdeda64a73416b3d
{
	meta:
		description = "Detects the use of 'fsockopen' with obfuscated characters in the code"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /[o0O]{3}\("fsockopen"\)/

	condition:
		any of them
}
