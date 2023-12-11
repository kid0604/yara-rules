import "pe"

rule SafeNetStrings : SafeNet Family
{
	meta:
		description = "Strings used by SafeNet"
		author = "Seth Hardy"
		last_modified = "2014-07-16"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "6dNfg8Upn5fBzGgj8licQHblQvLnUY19z5zcNKNFdsDhUzuI8otEsBODrzFCqCKr"
		$ = "/safe/record.php"
		$ = "_Rm.bat" wide ascii
		$ = "try\x0d\x0a\x09\x09\x09\x09  del %s" wide ascii
		$ = "Ext.org" wide ascii

	condition:
		any of them
}
