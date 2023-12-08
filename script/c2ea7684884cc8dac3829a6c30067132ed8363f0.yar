rule grelos_v
{
	meta:
		description = "Detects the presence of var grelos_v"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "var grelos_v"

	condition:
		any of them
}
