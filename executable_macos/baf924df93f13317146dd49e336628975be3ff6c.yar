import "pe"

rule APT_MAL_macOS_NK_3CX_Malicious_Samples_Mar23_1
{
	meta:
		description = "Detects malicious macOS application related to 3CX compromise (decrypted payload)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		date = "2023-03-30"
		score = 80
		hash1 = "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb"
		hash2 = "ac99602999bf9823f221372378f95baa4fc68929bac3a10e8d9a107ec8074eca"
		hash3 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "20230313064152Z0"
		$s2 = "Developer ID Application: 3CX (33CF4654HL)"

	condition:
		( uint16(0)==0xfeca or uint16(0)==0xfacf or uint32(0)==0xbebafeca) and all of them
}
