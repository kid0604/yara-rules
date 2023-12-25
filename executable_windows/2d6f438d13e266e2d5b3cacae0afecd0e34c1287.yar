rule win_marsStealer_encryption_bytecodes
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Encryption observed in MarsStealer"
		sha_256 = "7a391340b6677f74bcf896b5cc16a470543e2a384049df47949038df5e770df1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {31 2d 3d 31 73 30 02 39 c0 74 0a 5b 70 61 73 64 6c 30 71 77 69 8d 5b 01 8d 52 01 39 eb 75 03 83 eb 20 39 ca}

	condition:
		$s1
}
