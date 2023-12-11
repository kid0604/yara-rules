rule LNKR_JS_b
{
	meta:
		id = "FooEUkiF1qekRyatQeewJ"
		fingerprint = "bcc81d81472d21d4fdbd10f7713c77e7246b07644abf5c2a0c8e26bf3a2d2865"
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
		$ = "StartAll ok" ascii wide
		$ = "dexscriptid" ascii wide
		$ = "dexscriptpopup" ascii wide
		$ = "rid=LAUNCHED" ascii wide

	condition:
		3 of them
}
