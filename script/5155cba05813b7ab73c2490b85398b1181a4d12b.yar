rule eval_post
{
	meta:
		description = "Detects the use of eval with $_POST in PHP scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "eval(base64_decode($_POST"
		$ = "eval($undecode($tongji))"
		$ = "eval($_POST"

	condition:
		any of them
}
