rule Advapi_Hash_API
{
	meta:
		author = "_pusher_"
		description = "Looks for advapi API functions"
		date = "2016-07"
		os = "windows"
		filetype = "executable"

	strings:
		$advapi32 = "advapi32.dll" wide ascii nocase
		$CryptCreateHash = "CryptCreateHash" wide ascii
		$CryptHashData = "CryptHashData" wide ascii
		$CryptAcquireContext = "CryptAcquireContext" wide ascii

	condition:
		$advapi32 and ($CryptCreateHash and $CryptHashData and $CryptAcquireContext)
}
