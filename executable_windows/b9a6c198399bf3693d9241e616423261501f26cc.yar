import "pe"

rule TurlaMosquito_Mal_3
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		date = "2018-02-22"
		hash1 = "443cd03b37fca8a5df1bbaa6320649b441ca50d1c1fcc4f5a7b94b95040c73d1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "InstructionerDLL.dll" fullword ascii
		$s1 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
		$s2 = "/scripts/m/query.php?id=" fullword wide
		$s3 = "SELECT * FROM AntiVirusProduct" fullword ascii
		$s4 = "Microsoft Update" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="88488fe0b8bcd6e379dea6433bb5d7d8" or (pe.exports("InstallRoutineW") and pe.exports("StartRoutine")) or $x1 or 3 of them )
}
