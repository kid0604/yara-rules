import "pe"

rule APT1_dbg_mess
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 debug messages and potential payload filenames"
		os = "windows"
		filetype = "executable"

	strings:
		$dbg1 = "Down file ok!" wide ascii
		$dbg2 = "Send file ok!" wide ascii
		$dbg3 = "Command Error!" wide ascii
		$dbg4 = "Pls choose target first!" wide ascii
		$dbg5 = "Alert!" wide ascii
		$dbg6 = "Pls press enter to make sure!" wide ascii
		$dbg7 = "Are you sure to " wide ascii
		$pay1 = "rusinfo.exe" wide ascii
		$pay2 = "cmd.exe" wide ascii
		$pay3 = "AdobeUpdater.exe" wide ascii
		$pay4 = "buildout.exe" wide ascii
		$pay5 = "DefWatch.exe" wide ascii
		$pay6 = "d.exe" wide ascii
		$pay7 = "em.exe" wide ascii
		$pay8 = "IMSCMig.exe" wide ascii
		$pay9 = "localfile.exe" wide ascii
		$pay10 = "md.exe" wide ascii
		$pay11 = "mdm.exe" wide ascii
		$pay12 = "mimikatz.exe" wide ascii
		$pay13 = "msdev.exe" wide ascii
		$pay14 = "ntoskrnl.exe" wide ascii
		$pay15 = "p.exe" wide ascii
		$pay16 = "otepad.exe" wide ascii
		$pay17 = "reg.exe" wide ascii
		$pay18 = "regsvr.exe" wide ascii
		$pay19 = "runinfo.exe" wide ascii
		$pay20 = "AdobeUpdate.exe" wide ascii
		$pay21 = "inetinfo.exe" wide ascii
		$pay22 = "svehost.exe" wide ascii
		$pay23 = "update.exe" wide ascii
		$pay24 = "NTLMHash.exe" wide ascii
		$pay25 = "wpnpinst.exe" wide ascii
		$pay26 = "WSDbg.exe" wide ascii
		$pay27 = "xcmd.exe" wide ascii
		$pay28 = "adobeup.exe" wide ascii
		$pay29 = "0830.bin" wide ascii
		$pay30 = "1001.bin" wide ascii
		$pay31 = "a.bin" wide ascii
		$pay32 = "ISUN32.EXE" wide ascii
		$pay33 = "AcroRD32.EXE" wide ascii
		$pay34 = "INETINFO.EXE" wide ascii

	condition:
		4 of ($dbg*) and 1 of ($pay*)
}
