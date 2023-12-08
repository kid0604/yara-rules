rule EXPL_Follina_CVE_2022_30190_Msdt_MSProtocolURI_May22
{
	meta:
		description = "Detects the malicious usage of the ms-msdt URI as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		date = "2022-05-30"
		modified = "2022-07-18"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		hash1 = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
		hash2 = "778cbb0ee4afffca6a0b788a97bc2f4855ceb69ddc5eaa230acfa2834e1aeb07"
		score = 80
		os = "windows"
		filetype = "document"

	strings:
		$re1 = /location\.href\s{0,20}=\s{0,20}"ms-msdt:/
		$a1 = "%6D%73%2D%6D%73%64%74%3A%2F" ascii

	condition:
		filesize >3KB and filesize <100KB and 1 of them
}
