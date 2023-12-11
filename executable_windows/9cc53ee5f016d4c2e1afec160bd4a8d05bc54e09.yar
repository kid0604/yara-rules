rule win_bruteratel_syscall_hashes_oct_2022
{
	meta:
		author = "Embee_Research @ Huntress"
		vendor = "Huntress"
		created = "2022/10/12"
		description = "Detection of Brute Ratel Badger via api hashes of Nt* functions. "
		os = "windows"
		filetype = "executable"

	strings:
		$hash1 = {89 4d 39 8c}
		$hash2 = {bd ca 3b d3}
		$hash3 = {b2 c1 06 ae}
		$hash4 = {74 eb 1d 4d}

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x00e8) and (2 of ($hash*))
}
