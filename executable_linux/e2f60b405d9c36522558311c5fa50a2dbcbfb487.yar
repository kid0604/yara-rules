import "pe"

rule MAL_APT_NK_Andariel_ELF_Backdoor_Fipps
{
	meta:
		author = "CISA.gov"
		description = "Detects a Linux backdoor named Fipps used by Andariel"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		date = "2024-07-25"
		score = 80
		id = "040bca78-8b7e-5397-8a2b-1ddeed59eea3"
		os = "linux"
		filetype = "executable"

	strings:
		$a = "found mac address"
		$b = "RecvThread"
		$c = "OpenSSL-1.0.0-fipps"
		$d = "Disconnected!"

	condition:
		uint32(0)==0x464c457f and all of them
}
