rule Crypt32_CryptBinaryToString_API
{
	meta:
		author = "_pusher_"
		description = "Looks for crypt32 CryptBinaryToStringA function"
		date = "2016-08"
		os = "windows"
		filetype = "executable"

	strings:
		$crypt32 = "crypt32.dll" wide ascii nocase
		$CryptBinaryToStringA = "CryptBinaryToStringA" wide ascii

	condition:
		$crypt32 and ($CryptBinaryToStringA)
}
