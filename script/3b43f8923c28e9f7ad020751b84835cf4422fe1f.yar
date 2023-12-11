rule LNKR_JS_c
{
	meta:
		id = "1QAyO1czEHnDRAk825ZUFn"
		fingerprint = "9c839a66b2212d9ae94cd4ccd0150ff1c9c34d3fa797f015afa742407a7f4d4b"
		version = "1.0"
		creation_date = "2021-04-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
		category = "MALWARE"
		malware_type = "ADWARE"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "var affid" ascii wide
		$ = "var alsotry_enabled" ascii wide
		$ = "var boot_time" ascii wide
		$ = "var checkinc" ascii wide
		$ = "var dom" ascii wide
		$ = "var fsgroup" ascii wide
		$ = "var gcheckrunning" ascii wide
		$ = "var kodom" ascii wide
		$ = "var last_keywords" ascii wide
		$ = "var trkid" ascii wide
		$ = "var uid" ascii wide
		$ = "var wcleared" ascii wide

	condition:
		3 of them
}
