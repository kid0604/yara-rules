rule Empire_Exploit_JBoss
{
	meta:
		description = "Detects Empire component - file Exploit-JBoss.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "9ea3e00b299e644551d90bbee0ce3e4e82445aa15dab7adb7fcc0b7f1fe4e653"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Exploit-JBoss" fullword ascii
		$s2 = "$URL = \"http$($SSL)://\" + $($Rhost) + ':' + $($Port)" ascii
		$s3 = "\"/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service" ascii
		$s4 = "http://blog.rvrsh3ll.net" fullword ascii
		$s5 = "Remote URL to your own WARFile to deploy." fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <10KB and 1 of them ) or all of them
}
