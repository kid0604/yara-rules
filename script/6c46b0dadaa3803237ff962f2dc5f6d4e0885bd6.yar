rule atob_js
{
	meta:
		description = "Detects the use of atob function in JavaScript code"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "this['eval'](this['atob']('"

	condition:
		any of them
}
