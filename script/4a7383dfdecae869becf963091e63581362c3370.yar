rule md5_f797dd5d8e13fe5c8898dbe3beb3cc5b
{
	meta:
		description = "Detects the presence of a specific string used for echoing a bad file in various file types"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "echo(\"FILE_Bad\");"

	condition:
		any of them
}
