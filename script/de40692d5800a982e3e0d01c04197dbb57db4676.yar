rule LNKR_JS_d
{
	meta:
		id = "ixfWYGMOBADN6j1c4HrnP"
		fingerprint = "ea7abac4ced554a26930c025a84bc5188eb195f2b3488628063f0be35c937a59"
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
		$ = "adTrack" ascii wide
		$ = "addFSBeacon" ascii wide
		$ = "addYBeacon" ascii wide
		$ = "algopopunder" ascii wide
		$ = "applyAdDesign" ascii wide
		$ = "applyGoogleDesign" ascii wide
		$ = "deleteElement" ascii wide
		$ = "fixmargin" ascii wide
		$ = "galgpop" ascii wide
		$ = "getCurrentKw" ascii wide
		$ = "getGoogleListing" ascii wide
		$ = "getParameterByName" ascii wide
		$ = "getXDomainRequest" ascii wide
		$ = "googlecheck" ascii wide
		$ = "hasGoogleListing" ascii wide
		$ = "insertAfter" ascii wide
		$ = "insertNext" ascii wide
		$ = "insertinto" ascii wide
		$ = "isGoogleNewDesign" ascii wide
		$ = "moreReq" ascii wide
		$ = "openInNewTab" ascii wide
		$ = "pagesurf" ascii wide
		$ = "replaceRel" ascii wide
		$ = "sendData" ascii wide
		$ = "sizeinc" ascii wide
		$ = "streamAds" ascii wide
		$ = "urlcleanup" ascii wide

	condition:
		10 of them
}
