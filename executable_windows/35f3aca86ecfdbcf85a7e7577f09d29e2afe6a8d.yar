rule MAL_IceId_Core_202104
{
	meta:
		author = "Thomas Barabosch, Telekom Security"
		date = "2021-04-12"
		description = "2021 Bokbot / Icedid core"
		reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
		os = "windows"
		filetype = "executable"

	strings:
		$internal_name = "fixed_loader64.dll" fullword
		$string0 = "mail_vault" wide fullword
		$string1 = "ie_reg" wide fullword
		$string2 = "outlook" wide fullword
		$string3 = "user_num" wide fullword
		$string4 = "cred" wide fullword
		$string5 = "Authorization: Basic" fullword
		$string6 = "VaultOpenVault" fullword
		$string7 = "sqlite3_free" fullword
		$string8 = "cookie.tar" fullword
		$string9 = "DllRegisterServer" fullword
		$string10 = "PT0S" wide

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ($internal_name or all of ($s*)) or all of them
}
