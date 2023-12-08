rule MD5_API
{
	meta:
		author = "_pusher_"
		description = "Looks for MD5 API"
		date = "2016-07"
		os = "windows"
		filetype = "executable"

	strings:
		$advapi32 = "advapi32.dll" wide ascii nocase
		$cryptdll = "cryptdll.dll" wide ascii nocase
		$MD5Init = "MD5Init" wide ascii
		$MD5Update = "MD5Update" wide ascii
		$MD5Final = "MD5Final" wide ascii

	condition:
		($advapi32 or $cryptdll) and ($MD5Init and $MD5Update and $MD5Final)
}
