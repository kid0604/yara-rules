rule Linux_Generic_Threat_094c1238
{
	meta:
		author = "Elastic Security"
		id = "094c1238-32e7-43b8-bf5e-187cf3a28c9f"
		fingerprint = "1b36f7415f215c6e39e9702ae6793fffd7c7ecce1884767b5c24a1e086101faf"
		creation_date = "2024-01-23"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "2bfe7d51d59901af345ef06dafd8f0e950dcf8461922999670182bfc7082befd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC 18 01 00 00 48 89 D3 41 89 F6 49 89 FF 64 48 8B 04 25 28 00 00 00 48 89 84 24 10 01 00 00 49 89 E4 4C 89 E7 E8 FD 08 00 00 48 89 DF E8 75 08 00 00 4C 89 E7 48 89 DE 89 C2 E8 F8 08 00 }

	condition:
		all of them
}
