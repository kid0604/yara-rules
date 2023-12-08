rule INDICATOR_KB_GoBuildID_GoDownloader
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Go build ID: \"1OzJqWaH4h1VtrLP-zk8/G9w32ha7_ziW1Fa-0Byj/gLtfhbXZ6i_W0e5e_tFF/ekG0n9hOcZjmwzRQnRqC\"" ascii
		$s2 = "Go build ID: \"kKxyj14l4NhGbuhOgzef/ab_yr_pUn6q2idYdoBhn/hFAjO_Yxc_rN6mHFuHM9/SmS3qmOyJBc_4xV_qg3B\"" ascii
		$s3 = "Go build ID: \"MiW7XJnQsBXxlBHro8GW/HMqQknRgJg-mCXomgFRt/88ccKMrfA_s6AcOJs3aM/jSUAU_l3RrMzlV6ANEYE\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
