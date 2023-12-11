rule amasty_biz
{
	meta:
		description = "Detects the presence of amasty_biz"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "118,97,114,32,115,110,100,32,61,110,117,108,108,59,10,10,102,117"

	condition:
		any of them
}
