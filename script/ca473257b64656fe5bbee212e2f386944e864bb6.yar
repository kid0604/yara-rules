rule md5_4adef02197f50b9cc6918aa06132b2f6
{
	meta:
		description = "Detects suspicious JavaScript eval function usage"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\{\s*eval\s*\(\s*\$.{1,5}\s*\(\$\{\s*\$.{1,5}\s*\}\[\s*'.{1,10}'\s*\]\s*\)\s*\);\}/

	condition:
		any of them
}
