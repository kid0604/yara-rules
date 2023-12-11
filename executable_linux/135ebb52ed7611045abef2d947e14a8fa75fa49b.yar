rule Linux_Trojan_Gafgyt_656bf077
{
	meta:
		author = "Elastic Security"
		id = "656bf077-ca0c-4d28-9daa-eb6baafaf467"
		fingerprint = "3ea8ed60190198d5887bb7093975d648a9fd78234827d648a8258008c965b1c1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt based on specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 74 28 48 8B 45 E8 0F B6 00 84 C0 74 14 48 8B 75 E8 48 FF C6 48 8B }

	condition:
		all of them
}
