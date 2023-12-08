import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_References_Sandbox_Artifacts
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing sandbox artifacts"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\agent\\agent.pyw" ascii wide
		$s2 = "C:\\sandbox\\starter.exe" ascii wide
		$s3 = "c:\\ipf\\BDCore_U.dll" ascii wide
		$s4 = "C:\\cwsandbox_manager" ascii wide
		$s5 = "C:\\cwsandbox" ascii wide
		$s6 = "C:\\Stuff\\odbg110" ascii wide
		$s7 = "C:\\gfisandbox" ascii wide
		$s8 = "C:\\Virus Analysis" ascii wide
		$s9 = "C:\\iDEFENSE\\SysAnalyzer" ascii wide
		$s10 = "c:\\gnu\\bin" ascii wide
		$s11 = "C:\\SandCastle\\tools" ascii wide
		$s12 = "C:\\cuckoo\\dll" ascii wide
		$s13 = "C:\\MDS\\WinDump.exe" ascii wide
		$s14 = "C:\\tsl\\Raptorclient.exe" ascii wide
		$s15 = "C:\\guest_tools\\start.bat" ascii wide
		$s16 = "C:\\tools\\aswsnx\\snxcmd.exe" ascii wide
		$s17 = "C:\\Winap\\ckmon.pyw" ascii wide
		$s18 = "c:\\tools\\decodezeus" ascii wide
		$s19 = "c:\\tools\\aswsnx" ascii wide
		$s20 = "C:\\sandbox\\starter.exe" ascii wide
		$s21 = "C:\\Kit\\procexp.exe" ascii wide
		$s22 = "c:\\tracer\\mdare32_0.sys" ascii wide
		$s23 = "C:\\tool\\malmon" ascii wide
		$s24 = "C:\\Samples\\102114\\Completed" ascii wide
		$s25 = "c:\\vmremote\\VmRemoteGuest.exe" ascii wide
		$s26 = "d:\\sandbox_svc.exe" ascii wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
