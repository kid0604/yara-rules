rule APT_APT28_drovorub_library_and_unique_strings
{
	meta:
		description = "Rule to detect Drovorub-server, Drovorub-agent, and Drovorub-client"
		author = "NSA / FBI"
		reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
		date = "2020-08-13"
		score = 75
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "Poco" ascii wide
		$s2 = "Json" ascii wide
		$s3 = "OpenSSL" ascii wide
		$a1 = "clientid" ascii wide
		$a2 = "-----BEGIN" ascii wide
		$a3 = "-----END" ascii wide
		$a4 = "tunnel" ascii wide

	condition:
		( filesize >1MB and filesize <10MB and ( uint32(0)==0x464c457f)) and (#s1>20 and #s2>15 and #s3>15 and all of ($a*))
}
