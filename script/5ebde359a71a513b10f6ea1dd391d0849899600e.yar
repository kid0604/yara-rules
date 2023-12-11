rule LNKR_JS_a
{
	meta:
		id = "2ptjcpBqa9yDFmKpt0AW5C"
		fingerprint = "371d54a77d89c53acc9135095361279f9ecd479ec403f6a14bc393ec0032901b"
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
		$ = "AMZN_SEARCH" ascii wide
		$ = "BANNER_LOAD" ascii wide
		$ = "CB_FSI_ANSWER" ascii wide
		$ = "CB_FSI_BLIND_NO_URL" ascii wide
		$ = "CB_FSI_BREAK" ascii wide
		$ = "CB_FSI_DISPLAY" ascii wide
		$ = "CB_FSI_DO_BLIND" ascii wide
		$ = "CB_FSI_ERROR_EXCEPTION" ascii wide
		$ = "CB_FSI_ERROR_PARSERESULT" ascii wide
		$ = "CB_FSI_ERROR_TIMEOUT" ascii wide
		$ = "CB_FSI_ERR_INVRELINDEX" ascii wide
		$ = "CB_FSI_ERR_INV_BLIND_POS" ascii wide
		$ = "CB_FSI_FUSEARCH" ascii wide
		$ = "CB_FSI_FUSEARCH_ORGANIC" ascii wide
		$ = "CB_FSI_INJECT_EMPTY" ascii wide
		$ = "CB_FSI_OPEN" ascii wide
		$ = "CB_FSI_OPTOUTED" ascii wide
		$ = "CB_FSI_OPTOUT_DO" ascii wide
		$ = "CB_FSI_ORGANIC_RESULT" ascii wide
		$ = "CB_FSI_ORGANIC_SHOW" ascii wide
		$ = "CB_FSI_ORGREDIR" ascii wide
		$ = "CB_FSI_SKIP" ascii wide
		$ = "MNTZ_INJECT" ascii wide
		$ = "MNTZ_LOADED" ascii wide
		$ = "OPTOUT_SHOW" ascii wide
		$ = "PROMO_ANLZ" ascii wide
		$ = "URL_IGNOREDOMAIN" ascii wide
		$ = "URL_STATICFILE" ascii wide

	condition:
		5 of them
}
