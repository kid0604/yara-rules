rule BlackTech_HeavyROTLoader
{
	meta:
		description = "HeavyROT Loader in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "F32318060B58EA8CD458358B4BAE1F82E073D1567B9A29E98EB887860CEC563C"
		os = "windows"
		filetype = "executable"

	strings:
		$t1 = { 68 D8 A6 08 00 E8 }
		$t2 = { 43 81 FB 00 97 49 01 }
		$calc_key = { 63 51 E1 B7 8B ?? 8B ?? 81 ?? 00 10 00 00 C1 ?? 10 0B }
		$parse_data = { 8D 6F EE 8B 10 66 8B 70 10 8B 58 04 89 54 24 28 8B 50 08 3B F5 }

	condition:
		all of ($t*) or $calc_key or $parse_data
}
