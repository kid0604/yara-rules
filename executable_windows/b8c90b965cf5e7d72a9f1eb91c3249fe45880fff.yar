import "pe"

rule MALWARE_Win_PowerPool_STG1
{
	meta:
		author = "ditekSHen"
		description = "Detects first stage PowerPool backdoor"
		snort2_sid = "920088"
		snort3_sid = "920086"
		clamav_sig = "MALWARE.Win.Trojan.PowerPool-STG-1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd /c powershell.exe $PSVersionTable.PSVersion > \"%s\"" fullword wide
		$s2 = "cmd /c powershell.exe \"%s\" > \"%s\"" fullword wide
		$s3 = "rar.exe a -r %s.rar -ta%04d%02d%02d%02d%02d%02d -tb%04d%02d%02d%02d%02d%02d" fullword wide
		$s4 = "MyDemonMutex%d" fullword wide
		$s5 = "MyScreen.jpg" fullword wide
		$s6 = "proxy.log" fullword wide
		$s7 = "myjt.exe" fullword wide
		$s8 = "/?id=%s&info=%s" fullword wide
		$s9 = "auto.cfg" fullword ascii
		$s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64)" fullword wide
		$s11 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)" fullword wide
		$s12 = "CMD COMMAND EXCUTE ERROR!" fullword ascii
		$c1 = "run.afishaonline.eu" fullword wide
		$c2 = "home.Sports-Collectors.com" fullword wide
		$c3 = "about.Sports-Collectors.com" fullword
		$c4 = "179.43.158.15" fullword wide
		$c5 = "185.227.82.35" fullword wide

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or (1 of ($c*) and 5 of ($s*)))
}
