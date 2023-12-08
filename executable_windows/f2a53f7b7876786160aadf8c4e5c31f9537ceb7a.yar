import "pe"

rule HoneyBee_Dropper_MalDoc
{
	meta:
		description = "Detects samples from Operation Honeybee"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/JAHZVL"
		date = "2018-03-03"
		hash1 = "86981680172bbf0865e7693fe5a2bbe9b3ba12b3f1a1536ef67915daab78004c"
		hash2 = "0d4352322160339f87be70c2f3fe096500cfcdc95a8dea975fdfc457bd347c44"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd /c expand %TEMP%\\setup.cab -F:* %SystemRoot%\\System32"
		$x2 = "del /f /q %TEMP%\\setup.cab && cliconfg.exe"
		$s1 = "SELECT * FROM Win32_Processor" fullword ascii
		$s2 = "\"cmd /c `wusa " fullword ascii
		$s3 = "sTempPathP" fullword ascii
		$s4 = "sTempFile" fullword ascii
		$s5 = "GetObjectz" fullword ascii
		$s6 = "\\setup.cab" ascii

	condition:
		uint16(0)==0xcfd0 and filesize <400KB and (1 of ($x*) or 4 of them )
}
