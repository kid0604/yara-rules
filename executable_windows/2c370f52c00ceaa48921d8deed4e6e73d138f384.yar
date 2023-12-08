rule SystemBC_Config
{
	meta:
		id = "70WDDM1D5xtPBqsUdBiPTK"
		fingerprint = "8de029e2f4fc81742a3e04976a58360e403ce5737098c14e0a007c306a1e0f01"
		version = "1.0"
		creation_date = "2021-07-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies SystemBC RAT, decrypted config."
		category = "MALWARE"
		malware_type = "RAT"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "BEGINDATA" ascii wide fullword
		$ = "HOST1:" ascii wide fullword
		$ = "HOST2:" ascii wide fullword
		$ = "PORT1:" ascii wide fullword
		$ = "TOR:" ascii wide fullword
		$ = "-WindowStyle Hidden -ep bypass -file" ascii wide

	condition:
		3 of them
}
