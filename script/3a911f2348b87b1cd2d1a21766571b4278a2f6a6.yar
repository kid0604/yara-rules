rule eval_base64_decode_a
{
	meta:
		description = "Detects the use of eval(base64_decode($a)); in scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "eval(base64_decode($a));"

	condition:
		any of them
}
