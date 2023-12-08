import "pe"

rule Insta11Strings : Insta11 Family
{
	meta:
		description = "Insta11 Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-23"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "XTALKER7"
		$ = "Insta11 Microsoft" wide ascii
		$ = "wudMessage"
		$ = "ECD4FC4D-521C-11D0-B792-00A0C90312E1"
		$ = "B12AE898-D056-4378-A844-6D393FE37956"

	condition:
		any of them
}
