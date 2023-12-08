rule Msfpayloads_msf_5
{
	meta:
		description = "Metasploit Payloads - file msf.msi"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "required to install Foobar 1.0." fullword ascii
		$s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
		$s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii

	condition:
		all of them
}
