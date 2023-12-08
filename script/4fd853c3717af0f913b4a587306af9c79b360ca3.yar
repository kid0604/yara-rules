rule md5_0b1bfb0bdc7e017baccd05c6af6943ea
{
	meta:
		description = "Detects the use of eval function with obfuscated parameters"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /eval\([\w\d]+\(\$[\w\d]+, \$[\w\d]+\)\);/

	condition:
		any of them
}
