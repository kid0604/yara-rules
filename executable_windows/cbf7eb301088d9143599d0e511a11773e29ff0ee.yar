rule PurpleFox_b
{
	meta:
		id = "5dC5laJvjwww0AfMejPBAT"
		fingerprint = "84ade7b1f157b33b53d04b84689ad6ea4309abe40c2dad360825eb2f0e6a373b"
		version = "1.0"
		creation_date = "2021-11-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies PurpleFox aka DirtyMoe botnet."
		category = "MALWARE"
		os = "windows"
		filetype = "executable"

	strings:
		$ = /dump_[A-Z0-9]{8}/ ascii wide
		$ = "cscdll.dll" ascii wide
		$ = "sens.dll" ascii wide

	condition:
		all of them
}
