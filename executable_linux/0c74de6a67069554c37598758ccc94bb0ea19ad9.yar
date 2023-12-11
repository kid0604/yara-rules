rule Linux_Exploit_Openssl_47c6fad7
{
	meta:
		author = "Elastic Security"
		id = "47c6fad7-0582-4a7a-9c51-68830e6b6132"
		fingerprint = "bde819830cc991269275ce5de2db50489368c821271aaa397ab914011f2fcb91"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Openssl"
		reference_sample = "8024af0931dff24b5444f0b06a27366a776014358aa0b7fc073030958f863ef8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux OpenSSL Exploit"
		filetype = "executable"

	strings:
		$a = { 31 C9 F7 E1 51 5B B0 A4 CD 80 31 C0 50 68 2F }

	condition:
		all of them
}
