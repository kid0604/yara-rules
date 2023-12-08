rule mag_php_js
{
	meta:
		description = "Detects potential malicious keywords related to checkout pages in PHP and JavaScript files"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "onepage|checkout|onestep|firecheckout|onestepcheckout"
		$ = "'one|check'"

	condition:
		any of them
}
