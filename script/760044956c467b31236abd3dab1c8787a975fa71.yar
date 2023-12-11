rule thetech_org_js
{
	meta:
		description = "Detects JavaScript code related to onepage checkout on thetech.org website"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "|RegExp|onepage|checkout|"

	condition:
		any of them
}
