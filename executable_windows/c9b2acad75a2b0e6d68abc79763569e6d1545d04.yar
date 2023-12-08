import "pe"

rule ZXshell_20171211_chrsben
{
	meta:
		description = "Detects ZxShell variant surfaced in Dec 17"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/snc85M"
		date = "2017-12-11"
		hash1 = "dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "ncProxyXll" fullword ascii
		$s1 = "Uniscribe.dll" fullword ascii
		$s2 = "GetModuleFileNameDll" fullword ascii
		$s4 = "$Hangzhou Shunwang Technology Co.,Ltd0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (pe.imphash()=="de481441d675e9aca4f20bd8e16a5faa" or pe.exports("PerfectWorld") or pe.exports("ncProxyXll") or 1 of ($x*) or 2 of them )
}
