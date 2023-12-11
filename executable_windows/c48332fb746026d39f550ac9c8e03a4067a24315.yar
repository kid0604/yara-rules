import "pe"

rule APT17_Malware_Oct17_1
{
	meta:
		description = "Detects APT17 malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/puVc9q"
		date = "2017-10-03"
		hash1 = "dc9b5e8aa6ec86db8af0a7aa897ca61db3e5f3d2e0942e319074db1aaccfdc83"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" ascii
		$s2 = "\\spool\\prtprocs\\x64\\localspl.dll" ascii
		$s3 = "\\msvcrt.dll" ascii
		$s4 = "\\TSMSISrv.dll" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and all of them )
}
