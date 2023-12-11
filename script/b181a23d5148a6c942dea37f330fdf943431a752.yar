rule Unknown_Malware_Sample_Jul17_2
{
	meta:
		description = "Detects unknown malware sample with pastebin RAW URL"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/iqH8CK"
		date = "2017-08-01"
		hash1 = "3530d480db082af1823a7eb236203aca24dc3685f08c301466909f0794508a52"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
		$s2 = "https://pastebin.com/raw/" wide
		$s3 = "My.Computer" fullword ascii
		$s4 = "MyTemplate" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
