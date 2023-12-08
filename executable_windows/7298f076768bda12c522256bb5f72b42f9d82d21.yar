import "pe"

rule WPR_Passscape_Loader
{
	meta:
		description = "Windows Password Recovery - file ast.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "f6f2d4b9f19f9311ec419f05224a1c17cf2449f2027cb7738294479eea56e9cb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Services\\PasscapeLoader64" fullword wide
		$s2 = "ast64.dll" fullword ascii
		$s3 = "\\loader64.exe" wide
		$s4 = "Passcape 64-bit Loader Service" fullword wide
		$s5 = "PasscapeLoader64" fullword wide
		$s6 = "ast64 {msg1GkjN7Sh8sg2Al7ker63f}" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
