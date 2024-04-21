import "pe"

rule sig_17333_t_alt_1
{
	meta:
		description = "17333 - file t.xml"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "7ae52c0562755f909d5d79c81bb99ee2403f2c2ee4d53fd1ba7692c8053a63f6"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "      <Arguments>-ep bypass -windowstyle hidden -f \"C:\\Users\\Public\\module\\readKey.ps1\"</Arguments>" fullword wide
		$x2 = "      <Command>\"C:\\Users\\Public\\module\\module.exe\"</Command>" fullword wide
		$s3 = "      <Arguments>\"C:\\Users\\Public\\module\\module.ahk\"</Arguments>" fullword wide
		$s4 = "      <Command>powershell</Command>" fullword wide
		$s5 = "    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>" fullword wide
		$s6 = "  <Actions Context=\"Author\">" fullword wide
		$s7 = "    <Exec>" fullword wide
		$s8 = "    </Exec>" fullword wide
		$s9 = "    <LogonTrigger>" fullword wide
		$s10 = "    </LogonTrigger>" fullword wide
		$s11 = "      <LogonType>InteractiveToken</LogonType>" fullword wide
		$s12 = "      <RunLevel>LeastPrivilege</RunLevel>" fullword wide
		$s13 = "  </Actions>" fullword wide
		$s14 = "  </Settings>" fullword wide
		$s15 = "  </RegistrationInfo>" fullword wide
		$s16 = "  <Settings>" fullword wide
		$s17 = "  </Principals>" fullword wide
		$s18 = "  <Principals>" fullword wide
		$s19 = "  <RegistrationInfo>" fullword wide
		$s20 = "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword wide

	condition:
		uint16(0)==0xfeff and filesize <10KB and 1 of ($x*) and 4 of them
}
