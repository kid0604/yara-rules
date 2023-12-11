rule onepage_or_checkout
{
	meta:
		description = "Detects the presence of onepage or checkout related strings"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "\\x6F\\x6E\\x65\\x70\\x61\\x67\\x65\\x7C\\x63\\x68\\x65\\x63\\x6B\\x6F\\x75\\x74"

	condition:
		any of them
}
