import "pe"

rule MALWARE_Win_ZXShell_Loader
{
	meta:
		author = "ditekSHen"
		description = "Detects ZXShell kernel driver loader"
		hash1 = "a6020794bd6749e0765966cd65ca6d5511581f47cc2b38e41cb1e7fddaa0b221"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "KillAvpProcess" ascii wide nocase
		$s2 = "ProtectDllFile" ascii wide nocase
		$s3 = "LoadSys" ascii wide nocase
		$s4 = "CallDriver" ascii wide nocase
		$s5 = "DoRVA" fullword ascii wide
		$s6 = "TdiProxy" ascii
		$s7 = "res.ini" fullword ascii
		$s8 = "res.dat" fullword ascii
		$s9 = "google64.p" fullword ascii
		$s10 = "google32.p" fullword ascii
		$s11 = "OneSelfKey" fullword ascii
		$x1 = "antiscan" ascii
		$x2 = "removeprocessnotify" ascii
		$x3 = "setprocessnotify" ascii
		$x4 = "antiantigp" ascii
		$x5 = "hideproc" ascii
		$x6 = "hidekey" ascii
		$x7 = "hidefile" ascii
		$x8 = "sc create %s binpath= \"%%SystemRoot%%\\System32\\svchost.exe -k %s\" type= share start= auto" fullword ascii
		$m1 = "St4rtServ1ce" ascii
		$m2 = "ch3ck dr1ver failed" ascii
		$m3 = "L0ad dr1ver failed" ascii
		$m4 = "Write Dr1ver Failed" ascii
		$m5 = "over writed succ3ssfully" ascii
		$m6 = "can k1ll the pr0cessId" ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($m*) or 5 of ($s*) or 5 of ($x*) or (3 of ($s*) and 3 of ($x*)) or (2 of ($s*) and 1 of ($x*) and 1 of ($m*)) or (pe.exports("KillAvpProcess") and pe.exports("ProtectDllFile") and pe.exports("LoadSys")) or (3 of them and (pe.exports("KillAvpProcess") or pe.exports("ProtectDllFile") or pe.exports("LoadSys") or pe.exports("CallDriver") or pe.exports("DoRVA"))))
}
