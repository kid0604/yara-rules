rule Linux_Trojan_Tsunami_d74d7f0c
{
	meta:
		author = "Elastic Security"
		id = "d74d7f0c-70f8-4dd7-aaf4-fd5ab94bb8b2"
		fingerprint = "0a175d0ff64186d35b64277381f47dfafe559a42a3296a162a951f1b2add1344"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "b0a8b2259c00d563aa387d7e1a1f1527405da19bf4741053f5822071699795e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 20 79 6F 2C 0A 59 6A 02 5B 6A 04 58 CD 80 B3 7F 6A 01 58 CD }

	condition:
		all of them
}
