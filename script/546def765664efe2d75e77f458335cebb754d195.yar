rule function_through_object
{
	meta:
		description = "Detects the use of function_through_object in files"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "['eval']"
		$ = "['unescape']"
		$ = "['charCodeAt']"
		$ = "['fromCharCode']"

	condition:
		any of them and filesize <500KB
}
