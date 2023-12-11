rule md5_06e3ed58854daeacf1ed82c56a883b04
{
	meta:
		description = "Detects the use of serialize function in PHP code"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "$log_entry = serialize($ARINFO)"

	condition:
		any of them
}
