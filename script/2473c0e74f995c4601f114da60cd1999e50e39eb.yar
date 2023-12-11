rule jquery_code_su
{
	meta:
		description = "Detects suspicious jQuery code obfuscation"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "105,102,40,40,110,101,119,32,82,101,103,69,120,112,40,39,111,110,101,112,97,103,101"

	condition:
		any of them
}
