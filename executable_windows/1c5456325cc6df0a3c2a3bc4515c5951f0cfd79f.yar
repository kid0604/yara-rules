rule pos_chewbacca
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		reference = "https://www.securelist.com/en/blog/208214185/ChewBacca_a_new_episode_of_Tor_based_Malware"
		hashes = "21f8b9d9a6fa3a0cd3a3f0644636bf09, 28bc48ac4a92bde15945afc0cee0bd54"
		version = "0.2"
		description = "Testing the base64 encoded file in sys32"
		date = "01/30/2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "tor -f <torrc>"
		$s2 = "tor_"
		$s3 = "umemscan"
		$s4 = "CHEWBAC"

	condition:
		uint16(0)==0x5A4D and ( all of ($s*))
}
