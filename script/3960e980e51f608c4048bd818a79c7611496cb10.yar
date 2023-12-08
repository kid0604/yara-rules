rule obfuscated_eval
{
	meta:
		description = "Detects obfuscated eval function calls"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\\x65\s*\\x76\s*\\x61\s*\\x6C/
		$ = "\"/.*/e\""

	condition:
		any of them
}
