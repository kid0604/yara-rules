import "pe"

rule CobaltStrike_CN_Group_BeaconDropper_Aug17
{
	meta:
		description = "Detects Script Dropper of Cobalt Gang used in August 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-09"
		hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
		hash2 = "1c845bb0f6b9a96404af97dcafdc77f1629246e840c01dd9f1580a341f554926"
		hash3 = "6206e372870ea4f363be53557477f9748f1896831a0cdef3b8450a7fb65b86e1"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "WriteLine(\"(new ActiveXObject('WScript.Shell')).Run('cmd /c c:/" ascii
		$x2 = "WriteLine(\" (new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" ascii
		$x3 = "sh.Run(env('cmd /c set > %temp%" ascii
		$x4 = "sh.Run('regsvr32 /s /u /i:" ascii
		$x5 = ".Get('Win32_ScheduledJob').Create('regsvr32 /s /u /i:" ascii
		$x6 = "scrobj.dll','********" ascii
		$x7 = "www.thyssenkrupp-marinesystems.org" fullword ascii
		$x8 = "f.WriteLine(\" tLnk=env('%tmp%/'+lnkName+'.lnk');\");" fullword ascii
		$x9 = "lnkName='office 365'; " fullword ascii
		$x10 = ";sh=x('WScript.Shell');" ascii

	condition:
		( filesize <200KB and 1 of them )
}
