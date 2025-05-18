rule SUSP_RAR_NTFS_ADS
{
	meta:
		description = "Detects RAR archive with NTFS alternate data stream"
		author = "Proofpoint"
		category = "hunting"
		score = 70
		date = "2024-12-17"
		reference = "https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats"
		hash1 = "feec47858379c29300d249d1693f68dc085300f493891d1a9d4ea83b8db6e3c3"
		hash2 = "53a653aae9678075276bdb8ccf5eaff947f9121f73b8dcf24858c0447922d0b1"
		id = "ca2b5904-b3d3-53cd-a973-6f30f0831a94"
		os = "windows"
		filetype = "compressed"

	strings:
		$rar_magic = {52 61 72 21}
		$ads = {
                 03         // Header Type -> Service Header
                 23         // Header flags
                 [17-20]    // Flags and extra data area
                 00         // Windows
                 03         // Length of name = STM = 3
                 53 54 4d   // STM NTFS alternate data stream
                 [1-2]      // variable int (vint) for size of the stream name -> 1-2 bytes should be enough to take into account
                 07         // Data type = Service data = Service header data array
                 3a         // Start of the ADS name -> start with colon ":"
               }
		$neg = "Zone.Identifier"

	condition:
		$rar_magic at 0 and $ads and not $neg in (@ads[1]..@ads[1]+15)
}
